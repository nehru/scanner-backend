#!/usr/bin/env python3
"""
File Discovery and Extension Detection Service
First component of the multi-language scanner that handles path input and file discovery
"""

import os
import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

# Import your language configuration system
from scanner.core.language_config import create_config_manager, AsyncLanguageConfigManager

logger = logging.getLogger(__name__)

@dataclass
class DiscoveredFile:
    """Represents a discovered file with its language detection"""
    file_path: str
    extension: str
    detected_language: Optional[str]
    file_size: int
    last_modified: str

@dataclass
class DiscoveryResult:
    """Result of file discovery and extension detection"""
    input_path: str
    is_directory: bool
    total_files_found: int
    supported_files: Dict[str, List[DiscoveredFile]]  # language -> files
    unsupported_files: List[DiscoveredFile]
    supported_languages: List[str]
    discovery_duration: float
    timestamp: str

class FileDiscoveryService:
    """
    Service that handles file discovery and extension detection
    First stage of the scanner pipeline
    """
    
    def __init__(self, config_manager: AsyncLanguageConfigManager = None):
        self.config_manager = config_manager
        self.extension_to_language = {}
        self.supported_extensions = set()
        
        # Configuration
        self.max_file_size = 50 * 1024 * 1024  # 50MB limit
        self.excluded_dirs = {'.git', '.svn', 'node_modules', 'target', 'build', '.idea', 'out', '__pycache__'}
        self.excluded_extensions = {'.exe', '.dll', '.so', '.dylib', '.jar', '.war', '.zip', '.tar', '.gz'}
        
    async def initialize(self):
        """Initialize the service with language configuration"""
        if not self.config_manager:
            self.config_manager = await create_config_manager()
        
        # Build extension to language mapping
        self.extension_to_language = await self.config_manager.get_supported_extensions()
        self.supported_extensions = set(self.extension_to_language.keys())
        
        logger.info(f"FileDiscoveryService initialized with {len(self.supported_extensions)} supported extensions")
        logger.debug(f"Supported extensions: {sorted(self.supported_extensions)}")
    
    async def discover_files(self, input_path: str) -> DiscoveryResult:
        """
        Main discovery method that handles both files and directories
        
        Args:
            input_path: Path to file or directory to scan
            
        Returns:
            DiscoveryResult with discovered files organized by language
        """
        start_time = asyncio.get_event_loop().time()
        
        logger.info(f"Starting file discovery for: {input_path}")
        
        # Validate input path
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Path does not exist: {input_path}")
        
        # Determine if input is file or directory
        is_directory = os.path.isdir(input_path)
        
        if is_directory:
            discovered_files = await self._discover_directory(input_path)
        else:
            discovered_files = await self._discover_single_file(input_path)
        
        # Organize files by language
        supported_files = {}
        unsupported_files = []
        
        for file_info in discovered_files:
            if file_info.detected_language:
                if file_info.detected_language not in supported_files:
                    supported_files[file_info.detected_language] = []
                supported_files[file_info.detected_language].append(file_info)
            else:
                unsupported_files.append(file_info)
        
        # Calculate duration
        end_time = asyncio.get_event_loop().time()
        discovery_duration = end_time - start_time
        
        # Create result
        result = DiscoveryResult(
            input_path=input_path,
            is_directory=is_directory,
            total_files_found=len(discovered_files),
            supported_files=supported_files,
            unsupported_files=unsupported_files,
            supported_languages=list(supported_files.keys()),
            discovery_duration=discovery_duration,
            timestamp=datetime.now().isoformat()
        )
        
        logger.info(f"Discovery completed in {discovery_duration:.2f}s:")
        logger.info(f"  - Total files: {result.total_files_found}")
        logger.info(f"  - Supported languages: {result.supported_languages}")
        logger.info(f"  - Supported files: {sum(len(files) for files in supported_files.values())}")
        logger.info(f"  - Unsupported files: {len(unsupported_files)}")
        
        return result
    
    async def _discover_directory(self, directory_path: str) -> List[DiscoveredFile]:
        """Recursively discover files in a directory"""
        discovered_files = []
        
        for root, dirs, files in os.walk(directory_path):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if d not in self.excluded_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Process file asynchronously
                file_info = await self._process_file(file_path)
                if file_info:
                    discovered_files.append(file_info)
                
                # Yield control periodically
                if len(discovered_files) % 100 == 0:
                    await asyncio.sleep(0)
        
        return discovered_files
    
    async def _discover_single_file(self, file_path: str) -> List[DiscoveredFile]:
        """Process a single file"""
        file_info = await self._process_file(file_path)
        return [file_info] if file_info else []
    
    async def _process_file(self, file_path: str) -> Optional[DiscoveredFile]:
        """Process a single file and extract information"""
        try:
            # Get file stats
            stat_info = os.stat(file_path)
            file_size = stat_info.st_size
            last_modified = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            
            # Skip files that are too large
            if file_size > self.max_file_size:
                logger.debug(f"Skipping large file: {file_path} ({file_size} bytes)")
                return None
            
            # Extract extension
            file_extension = Path(file_path).suffix.lower()
            
            # Skip excluded extensions
            if file_extension in self.excluded_extensions:
                logger.debug(f"Skipping excluded extension: {file_path}")
                return None
            
            # Detect language
            detected_language = self.extension_to_language.get(file_extension)
            
            return DiscoveredFile(
                file_path=file_path,
                extension=file_extension,
                detected_language=detected_language,
                file_size=file_size,
                last_modified=last_modified
            )
            
        except (OSError, IOError) as e:
            logger.warning(f"Error processing file {file_path}: {e}")
            return None
    
    def get_supported_languages(self) -> List[str]:
        """Get list of all supported languages"""
        return list(set(self.extension_to_language.values()))
    
    def get_supported_extensions(self) -> List[str]:
        """Get list of all supported extensions"""
        return sorted(self.supported_extensions)
    
    async def validate_path(self, input_path: str) -> Tuple[bool, str]:
        """
        Validate if a path is accessible and scannable
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not input_path:
            return False, "Path cannot be empty"
        
        if not os.path.exists(input_path):
            return False, f"Path does not exist: {input_path}"
        
        if not os.access(input_path, os.R_OK):
            return False, f"Path is not readable: {input_path}"
        
        # Additional checks for directories
        if os.path.isdir(input_path):
            try:
                # Try to list directory contents
                os.listdir(input_path)
            except PermissionError:
                return False, f"Directory is not accessible: {input_path}"
        
        return True, "Path is valid"

# Standalone test function
async def test_file_discovery():
    """Test the file discovery service"""
    
    # Initialize service
    discovery_service = FileDiscoveryService()
    await discovery_service.initialize()
    
    # Test with your Java files directory
    test_path = r"C:\Users\nehru\app\app-32\java-files"
    
    print("=" * 60)
    print("FILE DISCOVERY SERVICE TEST")
    print("=" * 60)
    print(f"Testing path: {test_path}")
    
    # Validate path first
    is_valid, message = await discovery_service.validate_path(test_path)
    if not is_valid:
        print(f"Path validation failed: {message}")
        return
    
    print(f"Path validation: {message}")
    
    # Discover files
    try:
        result = await discovery_service.discover_files(test_path)
        
        # Print results
        print(f"\nDiscovery Results:")
        print(f"  Input path: {result.input_path}")
        print(f"  Is directory: {result.is_directory}")
        print(f"  Total files found: {result.total_files_found}")
        print(f"  Discovery duration: {result.discovery_duration:.2f} seconds")
        print(f"  Supported languages: {result.supported_languages}")
        
        # Show files by language
        for language, files in result.supported_files.items():
            print(f"\n{language.upper()} FILES ({len(files)}):")
            for file_info in files[:5]:  # Show first 5 files
                relative_path = os.path.relpath(file_info.file_path, test_path)
                print(f"  - {relative_path} ({file_info.extension}, {file_info.file_size} bytes)")
            if len(files) > 5:
                print(f"  ... and {len(files) - 5} more files")
        
        # Show unsupported files
        if result.unsupported_files:
            print(f"\nUNSUPPORTED FILES ({len(result.unsupported_files)}):")
            for file_info in result.unsupported_files[:3]:
                relative_path = os.path.relpath(file_info.file_path, test_path)
                print(f"  - {relative_path} ({file_info.extension})")
            if len(result.unsupported_files) > 3:
                print(f"  ... and {len(result.unsupported_files) - 3} more files")
        
        # Show extension mappings
        print(f"\nSUPPORTED EXTENSIONS:")
        extensions = discovery_service.get_supported_extensions()
        for ext in extensions[:10]:
            lang = discovery_service.extension_to_language[ext]
            print(f"  {ext} -> {lang}")
        if len(extensions) > 10:
            print(f"  ... and {len(extensions) - 10} more extensions")
        
        print("\n" + "=" * 60)
        print("FILE DISCOVERY TEST COMPLETED SUCCESSFULLY")
        print("=" * 60)
        
        return result
        
    except Exception as e:
        print(f"Discovery failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Run the test
    import sys
    import logging
    
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
    
    # Run test
    asyncio.run(test_file_discovery())
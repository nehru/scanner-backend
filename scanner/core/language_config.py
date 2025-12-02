#!/usr/bin/env python3
"""
scanner/core/language_config.py - Async WebSocket Version
Language Configuration Management for Multi-Language Scanner
Pure async implementation for WebSocket operation without threading
"""

import os
import yaml
import logging
import asyncio
import time
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class LanguageConfig:
    """Configuration for a specific programming language"""
    name: str
    extensions: List[str]
    rule_directories: List[str]
    custom_rules_filename: Optional[str]
    solutions_filename: Optional[str]
    description: Optional[str] = None
    enabled: bool = True
    
    def get_rule_paths(self, base_rules_dir: str) -> List[str]:
        """Get full paths to rule directories for this language"""
        return [os.path.join(base_rules_dir, rule_dir) for rule_dir in self.rule_directories]
    
    def get_custom_rules_path(self, custom_rules_base_dir: str) -> Optional[str]:
        """Get full path to custom rules file for this language"""
        if self.custom_rules_filename:
            return os.path.join(custom_rules_base_dir, self.custom_rules_filename)
        return None
    
    def get_solutions_path(self, solutions_base_dir: str) -> Optional[str]:
        """Get full path to solutions file for this language"""
        if self.solutions_filename:
            return os.path.join(solutions_base_dir, self.solutions_filename)
        return None

class AsyncLanguageConfigManager:
    """
    Async language configuration manager for WebSocket operation
    Pure async implementation without threading - optimized for real-time WebSocket scanning
    """
    
    def __init__(self, config_file_path: str = None):
        self.config_file_path = config_file_path or "config.yaml"
        self.languages: Dict[str, LanguageConfig] = {}
        
        # Async file tracking (no threading)
        self._last_modified = 0.0
        self._load_timestamp = 0.0
        self._loading_semaphore = asyncio.Semaphore(1)  # Prevent concurrent loads
        
        # Configuration will be loaded lazily when first accessed
        self._initialized = False
        
        logger.info(f"Async LanguageConfigManager created for: {self.config_file_path}")
    
    async def _load_configuration(self):
        """Async configuration loading from YAML file"""
        async with self._loading_semaphore:  # Prevent concurrent loads
            try:
                if not os.path.exists(self.config_file_path):
                    logger.warning(f"Configuration file not found: {self.config_file_path}, creating default config")
                    await self._create_default_configuration()
                    return
                
                # Track file modification time
                self._last_modified = os.path.getmtime(self.config_file_path)
                
                # Async file reading
                async with asyncio.Lock():  # Protect file reading
                    with open(self.config_file_path, 'r', encoding='utf-8') as f:
                        config_data = yaml.safe_load(f)
                
                if not config_data:
                    logger.warning("Empty configuration file, creating default config")
                    await self._create_default_configuration()
                    return
                
                # Handle missing 'languages' section
                if 'languages' not in config_data:
                    logger.warning("Missing 'languages' section, creating default config")
                    await self._create_default_configuration()
                    return
                
                # Clear existing configurations
                self.languages.clear()
                
                # Load each language configuration
                for lang_name, lang_config in config_data['languages'].items():
                    language_config = LanguageConfig(
                        name=lang_name,
                        extensions=lang_config.get('extensions', []),
                        rule_directories=lang_config.get('rule_directories', []),
                        custom_rules_filename=lang_config.get('custom_rules_filename'),
                        solutions_filename=lang_config.get('solutions_filename'),
                        description=lang_config.get('description'),
                        enabled=lang_config.get('enabled', True)
                    )
                    
                    # Validate required fields
                    if not language_config.extensions:
                        logger.warning(f"Language '{lang_name}' has no file extensions defined")
                    if not language_config.rule_directories:
                        logger.warning(f"Language '{lang_name}' has no rule directories defined")
                    
                    self.languages[lang_name] = language_config
                    logger.debug(f"Loaded configuration for language: {lang_name}")
                
                self._load_timestamp = time.time()
                self._initialized = True
                logger.info(f"Successfully loaded {len(self.languages)} language configurations")
                
            except Exception as e:
                logger.error(f"Failed to load language configuration: {e}")
                logger.info("Creating default configuration as fallback")
                await self._create_default_configuration()
    
    async def _create_default_configuration(self):
        """Create default configuration for all supported languages"""
        logger.info("Creating default language configuration")
        
        default_languages = {
            'java': {
                'extensions': ['.java', '.jsp', '.jspx'],
                'rule_directories': ['java/security'],
                'custom_rules_filename': 'java-rules.yml',
                'solutions_filename': 'java-solutions.yml',
                'description': 'Java security scanning',
                'enabled': True
            },
            'python': {
                'extensions': ['.py'],
                'rule_directories': ['python/security'],
                'custom_rules_filename': 'python-rules.yml',
                'solutions_filename': 'python-solutions.yml',
                'description': 'Python security scanning',
                'enabled': True
            },
            'javascript': {
                'extensions': ['.js', '.jsx'],
                'rule_directories': ['javascript/security'],
                'custom_rules_filename': 'javascript-rules.yml',
                'solutions_filename': 'javascript-solutions.yml',
                'description': 'JavaScript security scanning',
                'enabled': True
            },
            'typescript': {
                'extensions': ['.ts', '.tsx'],
                'rule_directories': ['typescript/security'],
                'custom_rules_filename': 'typescript-rules.yml',
                'solutions_filename': 'typescript-solutions.yml',
                'description': 'TypeScript security scanning',
                'enabled': True
            },
            'go': {
                'extensions': ['.go'],
                'rule_directories': ['go/security'],
                'custom_rules_filename': 'go-rules.yml',
                'solutions_filename': 'go-solutions.yml',
                'description': 'Go security scanning',
                'enabled': True
            },
            'rust': {
                'extensions': ['.rs'],
                'rule_directories': ['rust/security'],
                'custom_rules_filename': 'rust-rules.yml',
                'solutions_filename': 'rust-solutions.yml',
                'description': 'Rust security scanning',
                'enabled': True
            },
            'kotlin': {
                'extensions': ['.kt', '.kts'],
                'rule_directories': ['kotlin/security'],
                'custom_rules_filename': 'kotlin-rules.yml',
                'solutions_filename': 'kotlin-solutions.yml',
                'description': 'Kotlin security scanning',
                'enabled': True
            },
            'c': {
                'extensions': ['.c', '.h'],
                'rule_directories': ['c/security'],
                'custom_rules_filename': 'c-rules.yml',
                'solutions_filename': 'c-solutions.yml',
                'description': 'C security scanning',
                'enabled': True
            },
            'cpp': {
                'extensions': ['.cpp', '.cxx', '.cc', '.hpp', '.hxx'],
                'rule_directories': ['cpp/security'],
                'custom_rules_filename': 'cpp-rules.yml',
                'solutions_filename': 'cpp-solutions.yml',
                'description': 'C++ security scanning',
                'enabled': True
            },
            'scala': {
                'extensions': ['.scala'],
                'rule_directories': ['scala/security'],
                'custom_rules_filename': 'scala-rules.yml',
                'solutions_filename': 'scala-solutions.yml',
                'description': 'Scala security scanning',
                'enabled': True
            },
            'php': {
                'extensions': ['.php'],
                'rule_directories': ['php/security'],
                'custom_rules_filename': 'php-rules.yml',
                'solutions_filename': 'php-solutions.yml',
                'description': 'PHP security scanning',
                'enabled': True
            },
            'ruby': {
                'extensions': ['.rb'],
                'rule_directories': ['ruby/security'],
                'custom_rules_filename': 'ruby-rules.yml',
                'solutions_filename': 'ruby-solutions.yml',
                'description': 'Ruby security scanning',
                'enabled': True
            },
            'csharp': {
                'extensions': ['.cs'],
                'rule_directories': ['csharp/security'],
                'custom_rules_filename': 'csharp-rules.yml',
                'solutions_filename': 'csharp-solutions.yml',
                'description': 'C# security scanning',
                'enabled': True
            },
            'html': {
                'extensions': ['.html', '.htm'],
                'rule_directories': ['html/security'],
                'custom_rules_filename': 'html-rules.yml',
                'solutions_filename': 'html-solutions.yml',
                'description': 'HTML security scanning',
                'enabled': True
            },
            'css': {
                'extensions': ['.css'],
                'rule_directories': ['css/security'],
                'custom_rules_filename': 'css-rules.yml',
                'solutions_filename': 'css-solutions.yml',
                'description': 'CSS security scanning',
                'enabled': True
            },
            'sql': {
                'extensions': ['.sql'],
                'rule_directories': ['sql/security'],
                'custom_rules_filename': 'sql-rules.yml',
                'solutions_filename': 'sql-solutions.yml',
                'description': 'SQL security scanning',
                'enabled': True
            }
        }
        
        # Clear existing and add default configurations
        self.languages.clear()
        
        for lang_name, lang_config in default_languages.items():
            language_config = LanguageConfig(
                name=lang_name,
                extensions=lang_config['extensions'],
                rule_directories=lang_config['rule_directories'],
                custom_rules_filename=lang_config['custom_rules_filename'],
                solutions_filename=lang_config['solutions_filename'],
                description=lang_config['description'],
                enabled=lang_config['enabled']
            )
            
            self.languages[lang_name] = language_config
        
        self._load_timestamp = time.time()
        self._initialized = True
        logger.info(f"Created default configuration for {len(self.languages)} languages")
    
    async def _ensure_initialized(self):
        """Ensure configuration is loaded"""
        if not self._initialized:
            await self._load_configuration()
    
    async def get_language_config(self, language_name: str) -> Optional[LanguageConfig]:
        """Async retrieval of configuration for a specific language"""
        await self._ensure_initialized()
        
        # Check if configuration needs refresh
        await self._check_and_refresh_config()
        
        return self.languages.get(language_name)
    
    async def get_enabled_languages(self) -> Dict[str, LanguageConfig]:
        """Async retrieval of all enabled language configurations"""
        await self._ensure_initialized()
        await self._check_and_refresh_config()
        
        return {name: config for name, config in self.languages.items() if config.enabled}
    
    async def get_supported_extensions(self) -> Dict[str, str]:
        """Async retrieval of mapping of file extensions to language names"""
        await self._ensure_initialized()
        await self._check_and_refresh_config()
        
        extension_map = {}
        for lang_name, config in self.languages.items():
            if config.enabled:
                for ext in config.extensions:
                    if ext in extension_map:
                        logger.warning(f"Extension '{ext}' mapped to multiple languages: {extension_map[ext]} and {lang_name}")
                    extension_map[ext] = lang_name
        return extension_map
    
    async def list_languages(self) -> List[str]:
        """Async retrieval of all configured language names"""
        await self._ensure_initialized()
        await self._check_and_refresh_config()
        
        return list(self.languages.keys())
    
    async def reload_configuration(self, force: bool = False):
        """
        Async configuration reload
        
        Args:
            force: Force reload even if file hasn't changed
        """
        if not force and not await self._should_reload():
            logger.debug("Configuration file hasn't changed, skipping reload")
            return
        
        logger.info("Reloading language configuration...")
        old_count = len(self.languages)
        
        try:
            await self._load_configuration()
            new_count = len(self.languages)
            logger.info(f"Configuration reloaded: {old_count} -> {new_count} languages")
            
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")
            # Keep existing configuration on reload failure
            raise
    
    async def _should_reload(self) -> bool:
        """Async check if configuration file has been modified since last load"""
        try:
            if not os.path.exists(self.config_file_path):
                return False
            
            current_mtime = os.path.getmtime(self.config_file_path)
            return current_mtime > self._last_modified
            
        except OSError:
            logger.warning(f"Cannot check modification time for {self.config_file_path}")
            return False
    
    async def _check_and_refresh_config(self):
        """Check if config needs refresh and reload if necessary"""
        if await self._should_reload():
            try:
                logger.debug("Auto-reloading configuration due to file change")
                await self.reload_configuration(force=True)
            except Exception as e:
                logger.warning(f"Auto-reload failed, keeping existing config: {e}")
    
    async def validate_configuration(self) -> Dict[str, List[str]]:
        """Async validation of language configurations"""
        await self._ensure_initialized()
        await self._check_and_refresh_config()
        
        issues = {
            'errors': [],
            'warnings': [],
            'info': []
        }
        
        if not self.languages:
            issues['errors'].append("No languages configured")
            return issues
        
        # Check for duplicate extensions
        extension_count = {}
        for lang_name, config in self.languages.items():
            for ext in config.extensions:
                if ext not in extension_count:
                    extension_count[ext] = []
                extension_count[ext].append(lang_name)
        
        for ext, languages in extension_count.items():
            if len(languages) > 1:
                issues['warnings'].append(f"Extension '{ext}' is used by multiple languages: {', '.join(languages)}")
        
        # Check for missing required fields
        for lang_name, config in self.languages.items():
            if not config.extensions:
                issues['errors'].append(f"Language '{lang_name}' has no file extensions defined")
            if not config.rule_directories:
                issues['errors'].append(f"Language '{lang_name}' has no rule directories defined")
        
        # Add async information
        issues['info'].append("Async configuration management enabled")
        issues['info'].append("WebSocket-compatible operation")
        issues['info'].append(f"Configuration loaded at: {time.ctime(self._load_timestamp)}")
        issues['info'].append(f"File last modified: {time.ctime(self._last_modified)}")
        issues['info'].append("Auto-reload on file change: enabled")
        
        return issues
    
    async def get_config_info(self) -> Dict[str, any]:
        """Get comprehensive information about configuration state"""
        await self._ensure_initialized()
        
        return {
            'config_file_path': self.config_file_path,
            'total_languages': len(self.languages),
            'enabled_languages': len([config for config in self.languages.values() if config.enabled]),
            'load_timestamp': self._load_timestamp,
            'last_modified': self._last_modified,
            'needs_reload': await self._should_reload(),
            'languages': {
                name: {
                    'enabled': config.enabled,
                    'extensions': config.extensions,
                    'rule_directories': config.rule_directories,
                    'description': config.description
                }
                for name, config in self.languages.items()
            },
            'async_features': {
                'websocket_compatible': True,
                'auto_refresh': True,
                'file_tracking': True,
                'concurrent_safe': True,
                'no_threading': True
            }
        }
    
    async def enable_language(self, language_name: str) -> bool:
        """Async enable a language"""
        await self._ensure_initialized()
        
        if language_name in self.languages:
            self.languages[language_name].enabled = True
            logger.info(f"Enabled language: {language_name}")
            return True
        return False
    
    async def disable_language(self, language_name: str) -> bool:
        """Async disable a language"""
        await self._ensure_initialized()
        
        if language_name in self.languages:
            self.languages[language_name].enabled = False
            logger.info(f"Disabled language: {language_name}")
            return True
        return False
    
    async def get_async_status(self) -> Dict[str, bool]:
        """Get async operation status information"""
        return {
            'async_file_operations': True,
            'websocket_ready': True,
            'auto_refresh_enabled': True,
            'file_modification_tracking': True,
            'concurrent_access_safe': True,
            'no_threading_required': True,
            'lazy_initialization': True
        }

# Factory function to create async config manager
async def create_config_manager(config_file_path: str = None) -> AsyncLanguageConfigManager:
    """Create and initialize async language config manager"""
    config_manager = AsyncLanguageConfigManager(config_file_path)
    await config_manager._ensure_initialized()  # Initialize immediately
    return config_manager

# Convenience function for backward compatibility
async def create_async_language_config_manager(config_file_path: str = None) -> AsyncLanguageConfigManager:
    """Create and initialize async language config manager (alternative name)"""
    return await create_config_manager(config_file_path)
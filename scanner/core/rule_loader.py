#!/usr/bin/env python3
"""
scanner/core/rule_loader.py - Async WebSocket Version
Rule Loading Abstraction for Multi-Language Scanner
Simplified async version without threading complexity
"""

import os
import yaml
import asyncio
import logging
import time
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)

class LoadingState(Enum):
    """States for language rule loading"""
    NOT_LOADED = "not_loaded"
    LOADING = "loading"
    LOADED = "loaded"
    FAILED = "failed"

@dataclass
class RuleSet:
    """Container for loaded rules and metadata"""
    language: str
    semgrep_rules: List[Dict] = field(default_factory=list)
    custom_rules: List[Dict] = field(default_factory=list)
    solutions: Dict[str, str] = field(default_factory=dict)
    rule_directories: List[str] = field(default_factory=list)
    custom_rules_path: Optional[str] = None
    solutions_path: Optional[str] = None
    loaded_at: Optional[float] = None
    loading_duration: float = 0.0
    
    @property
    def all_rules(self) -> List[Dict]:
        """Get all rules combined"""
        return self.semgrep_rules + self.custom_rules
    
    @property
    def total_rules(self) -> int:
        """Get total number of rules"""
        return len(self.semgrep_rules) + len(self.custom_rules)
    
    def get_solution(self, rule_id: str) -> str:
        """Get solution for a rule with flexible matching"""
        # Direct match first
        if rule_id in self.solutions:
            return self.solutions[rule_id]
        
        # Try prefix stripping for semgrep rules
        prefixes_to_strip = [
            'semgrep-rules.java.security.',
            'custom-security-rules.java-',
            'custom-security-rules.',
            'semgrep-rules.',
            f'{self.language}.lang.security.audit.',
            f'{self.language}.spring.security.audit.',
            f'{self.language}.servlets.security.audit.',
            f'{self.language}.security.',
            f'{self.language}.',
        ]
        
        for prefix in prefixes_to_strip:
            if rule_id.startswith(prefix):
                stripped_id = rule_id[len(prefix):]
                if stripped_id in self.solutions:
                    logger.debug(f"Found solution for {rule_id} using stripped ID: {stripped_id}")
                    return self.solutions[stripped_id]
        
        # Try last part of dotted rule ID
        if '.' in rule_id:
            last_part = rule_id.split('.')[-1]
            if last_part in self.solutions:
                logger.debug(f"Found solution for {rule_id} using last part: {last_part}")
                return self.solutions[last_part]
        
        # Try partial matching
        for solution_key in self.solutions.keys():
            if solution_key in rule_id or rule_id.endswith(solution_key):
                logger.debug(f"Found solution for {rule_id} using partial match: {solution_key}")
                return self.solutions[solution_key]
        
        logger.warning(f"No solution found for rule: {rule_id}")
        return "No solution available"

@dataclass 
class LanguageRuleConfig:
    """Configuration for a language's rule loading"""
    language: str
    semgrep_rule_paths: List[str] = field(default_factory=list)
    custom_rules_filename: str = ""
    solutions_filename: str = ""
    enabled: bool = True
    
    def __post_init__(self):
        """Set default values based on language"""
        if not self.semgrep_rule_paths:
            self.semgrep_rule_paths = [f"{self.language}/security"]
        
        if not self.custom_rules_filename:
            self.custom_rules_filename = f"{self.language}-rules.yml"
        
        if not self.solutions_filename:
            self.solutions_filename = f"{self.language}-solutions.yml"

class AsyncRulePathBuilder:
    """Builds rule file paths following standard patterns - async version"""
    
    def __init__(self, base_config: Dict[str, str]):
        """Initialize with base directory configuration"""
        self.semgrep_base = base_config.get('semgrep_rules_base', 'semgrep-rules')
        self.custom_base = base_config.get('custom_security_rules_base', 'custom-security-rules') 
        self.solutions_base = base_config.get('solution_rules_base', 'solution-rules')
    
    async def get_semgrep_rule_directories(self, language_config: LanguageRuleConfig) -> List[str]:
        """Get absolute paths to semgrep rule directories"""
        directories = []
        for rule_path in language_config.semgrep_rule_paths:
            full_path = os.path.join(self.semgrep_base, rule_path)
            if os.path.exists(full_path):
                directories.append(os.path.abspath(full_path))
            else:
                logger.warning(f"Semgrep rule directory not found: {full_path}")
        return directories
    
    async def get_custom_rules_path(self, language_config: LanguageRuleConfig) -> Optional[str]:
        """Get path to custom rules file"""
        custom_path = os.path.join(self.custom_base, language_config.custom_rules_filename)
        if os.path.exists(custom_path):
            return os.path.abspath(custom_path)
        return None
    
    async def get_solutions_path(self, language_config: LanguageRuleConfig) -> Optional[str]:
        """Get path to solutions file"""
        solutions_path = os.path.join(self.solutions_base, language_config.solutions_filename)
        if os.path.exists(solutions_path):
            return os.path.abspath(solutions_path)
        return None

class AsyncFileLoader:
    """Async file loading for rules and solutions"""
    
    def __init__(self):
        self._file_cache: Dict[str, Tuple[float, Any]] = {}
        self._cache_ttl = 300  # 5 minutes cache TTL
        
    async def load_yaml_files_batch(self, file_paths: List[str]) -> List[Dict]:
        """Load multiple YAML files concurrently"""
        if not file_paths:
            return []
        
        logger.debug(f"Async batch loading {len(file_paths)} YAML files")
        
        # Load files concurrently
        tasks = [self._load_single_yaml_file(file_path) for file_path in file_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_rules = []
        loaded_files = 0
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(f"Failed to load YAML file {file_paths[i]}: {result}")
                continue
                
            if result:
                all_rules.extend(result)
                loaded_files += 1
        
        logger.debug(f"Async batch loaded {loaded_files} files, total rules: {len(all_rules)}")
        return all_rules
    
    async def _load_single_yaml_file(self, file_path: str) -> List[Dict]:
        """Load and validate rules from a single YAML file"""
        try:
            # Check cache first
            cached_data = await self._get_cached_file(file_path)
            if cached_data is not None:
                return cached_data
            
            # Load file asynchronously
            async with asyncio.Lock():  # Protect file reading
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    rule_data = yaml.safe_load(f)
            
            if not rule_data:
                return []
            
            # Handle different YAML structures
            rules_to_validate = []
            if isinstance(rule_data, dict):
                if 'rules' in rule_data:
                    rules_to_validate = rule_data['rules']
                else:
                    rules_to_validate = [rule_data]
            elif isinstance(rule_data, list):
                rules_to_validate = rule_data
            
            # Validate rules
            valid_rules = []
            for rule in rules_to_validate:
                if self._is_valid_rule(rule):
                    valid_rules.append(rule)
            
            # Cache the results
            await self._cache_file(file_path, valid_rules)
            
            return valid_rules
            
        except Exception as e:
            logger.error(f"Error loading YAML file {file_path}: {e}")
            return []
    
    async def _get_cached_file(self, file_path: str) -> Optional[List[Dict]]:
        """Get cached file data if still valid"""
        if file_path not in self._file_cache:
            return None
        
        cached_time, cached_data = self._file_cache[file_path]
        
        # Check TTL
        if time.time() - cached_time > self._cache_ttl:
            del self._file_cache[file_path]
            return None
        
        # Check if file was modified
        try:
            file_mtime = os.path.getmtime(file_path)
            if file_mtime > cached_time:
                del self._file_cache[file_path]
                return None
        except OSError:
            del self._file_cache[file_path]
            return None
        
        logger.debug(f"Using cached data for {file_path}")
        return cached_data
    
    async def _cache_file(self, file_path: str, data: List[Dict]) -> None:
        """Cache file data with timestamp"""
        self._file_cache[file_path] = (time.time(), data)
    
    def _is_valid_rule(self, rule: Dict) -> bool:
        """Validate that a rule has required fields"""
        if not isinstance(rule, dict):
            return False
        
        # Check essential fields
        essential_fields = ['id', 'message', 'languages']
        for field in essential_fields:
            if field not in rule:
                return False
        
        # Check for pattern configuration
        pattern_fields = [
            'pattern', 'patterns', 'pattern-regex', 'pattern-not',
            'pattern-either', 'pattern-inside', 'pattern-not-inside',
            'pattern-sources', 'pattern-sinks'
        ]
        
        has_pattern = any(field in rule for field in pattern_fields)
        if not has_pattern and rule.get('mode') == 'taint':
            has_pattern = 'pattern-sources' in rule and 'pattern-sinks' in rule
        
        return has_pattern
    
    def clear_cache(self) -> None:
        """Clear the file cache"""
        self._file_cache.clear()
        logger.debug("File cache cleared")

class AsyncRuleLoader:
    """Async rule loader for different sources"""
    
    def __init__(self):
        self.file_loader = AsyncFileLoader()
    
    async def load_semgrep_rules(self, directories: List[str]) -> List[Dict]:
        """Load semgrep rules from directories concurrently"""
        all_files = []
        
        # Collect all YAML files from all directories
        for rule_dir in directories:
            logger.info(f"Scanning semgrep rules directory: {rule_dir}")
            
            try:
                for root, dirs, files in os.walk(rule_dir):
                    for file in files:
                        if file.endswith(('.yml', '.yaml')) and not file.endswith('.test.yaml'):
                            rule_file = os.path.join(root, file)
                            all_files.append(rule_file)
            except Exception as e:
                logger.error(f"Error scanning rule directory {rule_dir}: {e}")
        
        # Load all files concurrently
        if all_files:
            logger.info(f"Async loading {len(all_files)} semgrep rule files")
            all_rules = await self.file_loader.load_yaml_files_batch(all_files)
            logger.info(f"Loaded {len(all_rules)} semgrep rules from {len(all_files)} files")
            return all_rules
        
        return []
    
    async def load_custom_rules(self, custom_rules_path: str) -> List[Dict]:
        """Load custom rules from YAML file"""
        if not custom_rules_path or not os.path.exists(custom_rules_path):
            return []
        
        try:
            logger.info(f"Loading custom rules from: {custom_rules_path}")
            rules = await self.file_loader.load_yaml_files_batch([custom_rules_path])
            logger.info(f"Loaded {len(rules)} custom rules")
            return rules
        except Exception as e:
            logger.error(f"Failed to load custom rules from {custom_rules_path}: {e}")
            return []
    
    async def load_solutions(self, solutions_path: str) -> Dict[str, str]:
        """Load solutions from YAML file"""
        if not solutions_path or not os.path.exists(solutions_path):
            return {}
        
        try:
            logger.info(f"Loading solutions from: {solutions_path}")
            
            async with asyncio.Lock():  # Protect file reading
                with open(solutions_path, 'r', encoding='utf-8') as f:
                    solutions_data = yaml.safe_load(f)
            
            solutions_dict = {}
            if solutions_data and 'solutions' in solutions_data:
                for item in solutions_data['solutions']:
                    if isinstance(item, dict) and 'id' in item and 'solution' in item:
                        rule_id = item['id']
                        solution = item['solution']
                        solutions_dict[rule_id] = str(solution) if solution else ""
            
            logger.info(f"Loaded {len(solutions_dict)} solutions")
            return solutions_dict
            
        except Exception as e:
            logger.error(f"Failed to load solutions from {solutions_path}: {e}")
            return {}
    
    async def extract_solutions_from_rules(self, rules: List[Dict]) -> Dict[str, str]:
        """Extract solutions from rule metadata"""
        solutions = {}
        
        for rule in rules:
            if not isinstance(rule, dict) or 'id' not in rule:
                continue
                
            rule_id = rule['id']
            metadata = rule.get('metadata', {})
            
            if isinstance(metadata, dict) and 'solution' in metadata:
                solution = metadata['solution']
                if solution and str(solution).strip():
                    solutions[rule_id] = str(solution).strip()
                    logger.debug(f"Extracted solution for rule: {rule_id}")
        
        if solutions:
            logger.info(f"Extracted {len(solutions)} solutions from rule metadata")
        
        return solutions

class AsyncRuleLoaderManager:
    """
    Async rule loading manager - simplified without threading
    Single instance for WebSocket operation
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._cache: Dict[str, RuleSet] = {}
        self._loading_states: Dict[str, LoadingState] = {}
        
        # Configuration
        self._language_configs: Dict[str, LanguageRuleConfig] = {}
        self._base_config: Dict[str, str] = {}
        self._path_builder: Optional[AsyncRulePathBuilder] = None
        self._rule_loader = AsyncRuleLoader()
        
        self._initialized = True
        logger.info("Async RuleLoaderManager initialized")
    
    async def configure(self, base_config: Dict[str, str], language_configs: Dict[str, Dict[str, Any]] = None):
        """Configure the rule loader with base paths and language-specific configs"""
        self._base_config = base_config
        self._path_builder = AsyncRulePathBuilder(base_config)
        
        # Set up language configurations
        if language_configs:
            for lang, config in language_configs.items():
                self._language_configs[lang] = LanguageRuleConfig(
                    language=lang,
                    semgrep_rule_paths=config.get('semgrep_rule_paths', []),
                    custom_rules_filename=config.get('custom_rules_filename', f"{lang}-rules.yml"),
                    solutions_filename=config.get('solutions_filename', f"{lang}-solutions.yml"),
                    enabled=config.get('enabled', True)
                )
        
        # Create default configs for all 14 supported languages
        await self._create_default_language_configs()
        
        logger.info(f"Configured async rule loader for {len(self._language_configs)} languages")
    
    async def _create_default_language_configs(self):
        """Create default configurations for all supported languages"""
        default_languages = [
            'java', 'python', 'javascript', 'typescript', 'go', 'rust',
            'kotlin', 'c', 'cpp', 'scala', 'php', 'ruby', 'csharp', 'html', 'css', 'sql'
        ]
        
        for lang in default_languages:
            if lang not in self._language_configs:
                self._language_configs[lang] = LanguageRuleConfig(
                    language=lang,
                    semgrep_rule_paths=[f"{lang}/security"],
                    custom_rules_filename=f"{lang}-rules.yml",
                    solutions_filename=f"{lang}-solutions.yml",
                    enabled=True
                )
    
    async def get_rules_for_language(self, language: str, force_reload: bool = False) -> RuleSet:
        """Get rules for a language with async loading"""
        # Check cache first
        if not force_reload and language in self._cache:
            logger.debug(f"Using cached rules for {language}")
            return self._cache[language]
        
        # Check if already loading
        if language in self._loading_states and self._loading_states[language] == LoadingState.LOADING:
            logger.debug(f"Language {language} is already loading, waiting...")
            # Simple wait with timeout
            for _ in range(30):  # 30 seconds max wait
                await asyncio.sleep(1)
                if language in self._cache:
                    return self._cache[language]
                if self._loading_states.get(language) != LoadingState.LOADING:
                    break
        
        # Load the rules
        try:
            self._loading_states[language] = LoadingState.LOADING
            ruleset = await self._load_language_rules(language)
            
            # Cache the results
            self._cache[language] = ruleset
            self._loading_states[language] = LoadingState.LOADED
            
            logger.info(f"Loaded rules for {language}: {ruleset.total_rules} rules, {len(ruleset.solutions)} solutions")
            return ruleset
            
        except Exception as e:
            error_msg = f"Failed to load rules for {language}: {str(e)}"
            logger.error(error_msg)
            
            self._loading_states[language] = LoadingState.FAILED
            return self._create_empty_ruleset(language)
    
    async def _load_language_rules(self, language: str) -> RuleSet:
        """Load rules for a specific language"""
        start_time = time.time()
        
        # Check if language is configured
        if language not in self._language_configs:
            logger.warning(f"No configuration found for language: {language}")
            self._language_configs[language] = LanguageRuleConfig(language=language)
        
        language_config = self._language_configs[language]
        
        if not language_config.enabled:
            logger.info(f"Language {language} is disabled, returning empty ruleset")
            return self._create_empty_ruleset(language)
        
        logger.info(f"Loading rules for language: {language}")
        
        # Get file paths
        semgrep_directories = await self._path_builder.get_semgrep_rule_directories(language_config)
        custom_rules_path = await self._path_builder.get_custom_rules_path(language_config)
        solutions_path = await self._path_builder.get_solutions_path(language_config)
        
        # Load rules concurrently
        tasks = [
            self._rule_loader.load_semgrep_rules(semgrep_directories),
            self._rule_loader.load_custom_rules(custom_rules_path) if custom_rules_path else asyncio.sleep(0, result=[]),
            self._rule_loader.load_solutions(solutions_path) if solutions_path else asyncio.sleep(0, result={})
        ]
        
        semgrep_rules, custom_rules, solutions = await asyncio.gather(*tasks)
        
        # Extract solutions from rule metadata
        all_rules = semgrep_rules + custom_rules
        extracted_solutions = await self._rule_loader.extract_solutions_from_rules(all_rules)
        solutions.update(extracted_solutions)
        
        # Create ruleset
        load_duration = time.time() - start_time
        ruleset = RuleSet(
            language=language,
            semgrep_rules=semgrep_rules,
            custom_rules=custom_rules,
            solutions=solutions,
            rule_directories=semgrep_directories,
            custom_rules_path=custom_rules_path,
            solutions_path=solutions_path,
            loaded_at=time.time(),
            loading_duration=load_duration
        )
        
        logger.info(f"Loaded rules for {language} in {load_duration:.2f}s:")
        logger.info(f"  - Semgrep rules: {len(semgrep_rules)}")
        logger.info(f"  - Custom rules: {len(custom_rules)}")
        logger.info(f"  - Solutions: {len(solutions)}")
        
        return ruleset
    
    def _create_empty_ruleset(self, language: str) -> RuleSet:
        """Create an empty ruleset for error cases"""
        return RuleSet(
            language=language,
            loaded_at=time.time(),
            loading_duration=0.0
        )
    
    async def is_language_supported(self, language: str) -> bool:
        """Check if a language has rule configuration"""
        return language in self._language_configs
    
    async def get_supported_languages(self) -> List[str]:
        """Get list of supported languages"""
        return list(self._language_configs.keys())
    
    async def clear_cache(self, language: str = None):
        """Clear cached rules for a language or all languages"""
        if language:
            if language in self._cache:
                del self._cache[language]
                logger.info(f"Cleared cache for {language}")
            if language in self._loading_states:
                del self._loading_states[language]
        else:
            self._cache.clear()
            self._loading_states.clear()
            logger.info("Cleared all rule cache")
    
    async def get_cache_info(self) -> Dict[str, Any]:
        """Get information about cached rules and loading states"""
        cache_info = {}
        for language, ruleset in self._cache.items():
            cache_info[language] = {
                'total_rules': ruleset.total_rules,
                'semgrep_rules': len(ruleset.semgrep_rules),
                'custom_rules': len(ruleset.custom_rules),
                'solutions': len(ruleset.solutions),
                'loaded_at': ruleset.loaded_at,
                'loading_duration': ruleset.loading_duration
            }
        
        loading_states = {
            lang: state.value for lang, state in self._loading_states.items()
        }
        
        return {
            'cached_languages': list(self._cache.keys()),
            'configured_languages': list(self._language_configs.keys()),
            'cache_details': cache_info,
            'loading_states': loading_states,
            'async_features': {
                'concurrent_loading': True,
                'file_caching': True,
                'websocket_ready': True,
                'simplified_architecture': True
            }
        }
    
    async def validate_configuration(self) -> Dict[str, Any]:
        """Validate the rule loader configuration"""
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'language_status': {},
            'async_features': {
                'concurrent_loading': True,
                'simplified_caching': True,
                'websocket_compatible': True
            }
        }
        
        if not self._path_builder:
            validation_result['valid'] = False
            validation_result['errors'].append("AsyncRuleLoaderManager not configured")
            return validation_result
        
        # Validate each language configuration
        for language, config in self._language_configs.items():
            lang_status = {
                'configured': True,
                'semgrep_directories_found': 0,
                'custom_rules_found': False,
                'solutions_found': False,
                'errors': [],
                'warnings': []
            }
            
            try:
                # Check semgrep rule directories
                semgrep_dirs = await self._path_builder.get_semgrep_rule_directories(config)
                lang_status['semgrep_directories_found'] = len(semgrep_dirs)
                
                if not semgrep_dirs:
                    lang_status['warnings'].append("No semgrep rule directories found")
                
                # Check custom rules
                custom_path = await self._path_builder.get_custom_rules_path(config)
                lang_status['custom_rules_found'] = custom_path is not None
                
                # Check solutions
                solutions_path = await self._path_builder.get_solutions_path(config)
                lang_status['solutions_found'] = solutions_path is not None
                
            except Exception as e:
                lang_status['errors'].append(f"Configuration error: {e}")
                validation_result['valid'] = False
            
            validation_result['language_status'][language] = lang_status
        
        return validation_result

# Convenience function to get the singleton instance
def get_async_rule_loader() -> AsyncRuleLoaderManager:
    """Get the singleton async rule loader manager instance"""
    return AsyncRuleLoaderManager()

# Default configuration for WebSocket scanner
async def create_default_rule_config() -> Dict[str, str]:
    """Create default rule configuration matching directory structure"""
    return {
        'semgrep_rules_base': 'semgrep-rules',
        'custom_security_rules_base': 'custom-security-rules',
        'solution_rules_base': 'solution-rules'
    }
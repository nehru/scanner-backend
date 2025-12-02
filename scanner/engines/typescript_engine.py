import asyncio
import logging
from typing import List, Dict, Optional
from datetime import datetime

from ..core.language_config import AsyncLanguageConfigManager
from ..core.base_classes import BaseLanguageEngine, ScanResult, Vulnerability
from ..core.rule_loader import get_async_rule_loader

logger = logging.getLogger(__name__)

class AsyncTypeScriptEngine(BaseLanguageEngine):
    """Async TypeScript scanner engine"""
    
    def __init__(self, config_manager: AsyncLanguageConfigManager, semgrep_rules_base_dir: str = None, base_config: Optional[Dict] = None):
        super().__init__('typescript', None, base_config)
        self.config_manager = config_manager
        asyncio.create_task(self._configure_rule_loader(semgrep_rules_base_dir))
        
    async def _initialize_engine(self):
        self.language_config = await self.config_manager.get_language_config('typescript')
        if not self.language_config:
            raise ValueError("TypeScript language configuration not found")
        self.supported_extensions = self.language_config.extensions
        
    async def _configure_rule_loader(self, semgrep_rules_base_dir: str = None):
        rule_loader = get_async_rule_loader()
        base_config = {
            'semgrep_rules_base': semgrep_rules_base_dir or 'semgrep-rules',
            'custom_security_rules_base': 'custom-security-rules',
            'solution_rules_base': 'solution-rules'
        }
        language_configs = {
            'typescript': {
                'semgrep_rule_paths': ['typescript/security'],
                'custom_rules_filename': 'typescript-rules.yml',
                'solutions_filename': 'typescript-solutions.yml',
                'enabled': True
            }
        }
        await rule_loader.configure(base_config, language_configs)
        
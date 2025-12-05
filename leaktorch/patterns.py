"""
leaktorch/patterns.py
Secret pattern definitions and pattern management
"""

import re
from typing import Dict, List, Set
from dataclasses import dataclass


@dataclass
class PatternConfig:
    """Configuration for a secret pattern"""
    name: str
    pattern: str
    severity: str
    description: str = ""
    reduce_severity_if_in_comment: bool = True
    reduce_severity_if_in_test: bool = True
    
    def compile(self):
        """Compile the regex pattern"""
        return re.compile(self.pattern, re.IGNORECASE)


class PatternRegistry:
    """Registry for secret detection patterns"""
    
    CRITICAL = 'CRITICAL'
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    
    def __init__(self):
        self._patterns: Dict[str, PatternConfig] = {}
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._load_default_patterns()
    
    def _load_default_patterns(self):
        """Load default secret patterns"""
        
        self.register(PatternConfig(
            name='AWS Access Key',
            pattern=r'AKIA[0-9A-Z]{16}',
            severity=self.CRITICAL,
            description='AWS Access Key ID'
        ))
        
        self.register(PatternConfig(
            name='AWS Secret Key',
            pattern=r'aws(.{0,20})?[\'"][0-9a-zA-Z\/+]{40}[\'"]',
            severity=self.CRITICAL,
            description='AWS Secret Access Key'
        ))
        
        self.register(PatternConfig(
            name='AWS Session Token',
            pattern=r'aws.{0,20}token[\'"\s]*[:=][\'"\s]*[A-Za-z0-9/+=]{100,}',
            severity=self.CRITICAL,
            description='AWS Session Token'
        ))
        
        self.register(PatternConfig(
            name='GitHub Personal Access Token',
            pattern=r'ghp_[0-9a-zA-Z]{36}',
            severity=self.CRITICAL,
            description='GitHub Personal Access Token'
        ))
        
        self.register(PatternConfig(
            name='GitHub OAuth Token',
            pattern=r'gho_[0-9a-zA-Z]{36}',
            severity=self.CRITICAL,
            description='GitHub OAuth Access Token'
        ))
        
        self.register(PatternConfig(
            name='GitHub App Token',
            pattern=r'(ghu|ghs)_[0-9a-zA-Z]{36}',
            severity=self.CRITICAL,
            description='GitHub App/Server Token'
        ))
        
        self.register(PatternConfig(
            name='GitHub Refresh Token',
            pattern=r'ghr_[0-9a-zA-Z]{76}',
            severity=self.CRITICAL,
            description='GitHub Refresh Token'
        ))
        
        self.register(PatternConfig(
            name='GitLab Personal Access Token',
            pattern=r'glpat-[0-9a-zA-Z\-\_]{20}',
            severity=self.CRITICAL,
            description='GitLab Personal Access Token'
        ))
        
        self.register(PatternConfig(
            name='Google API Key',
            pattern=r'AIza[0-9A-Za-z\-_]{35}',
            severity=self.CRITICAL,
            description='Google API Key'
        ))
        
        self.register(PatternConfig(
            name='Google OAuth',
            pattern=r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            severity=self.CRITICAL,
            description='Google OAuth Client ID'
        ))
        
        self.register(PatternConfig(
            name='Google Cloud Service Account',
            pattern=r'"type":\s*"service_account"',
            severity=self.CRITICAL,
            description='Google Cloud Service Account JSON'
        ))
        
        self.register(PatternConfig(
            name='Slack Token',
            pattern=r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            severity=self.HIGH,
            description='Slack API Token'
        ))
        
        self.register(PatternConfig(
            name='Slack Webhook',
            pattern=r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
            severity=self.HIGH,
            description='Slack Webhook URL'
        ))
        
        self.register(PatternConfig(
            name='Stripe Live API Key',
            pattern=r'sk_live_[0-9a-zA-Z]{24,}',
            severity=self.CRITICAL,
            description='Stripe Live Secret Key'
        ))
        
        self.register(PatternConfig(
            name='Stripe Test API Key',
            pattern=r'sk_test_[0-9a-zA-Z]{24,}',
            severity=self.MEDIUM,
            description='Stripe Test Secret Key',
            reduce_severity_if_in_test=False
        ))
        
        self.register(PatternConfig(
            name='PayPal/Braintree Access Token',
            pattern=r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            severity=self.CRITICAL,
            description='PayPal/Braintree Access Token'
        ))
        
        self.register(PatternConfig(
            name='Twilio API Key',
            pattern=r'SK[0-9a-fA-F]{32}',
            severity=self.HIGH,
            description='Twilio API Key'
        ))
        
        self.register(PatternConfig(
            name='SendGrid API Key',
            pattern=r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
            severity=self.HIGH,
            description='SendGrid API Key'
        ))
        
        self.register(PatternConfig(
            name='Mailgun API Key',
            pattern=r'key-[0-9a-zA-Z]{32}',
            severity=self.HIGH,
            description='Mailgun API Key'
        ))
        
        self.register(PatternConfig(
            name='RSA Private Key',
            pattern=r'-----BEGIN RSA PRIVATE KEY-----',
            severity=self.CRITICAL,
            description='RSA Private Key',
            reduce_severity_if_in_comment=False
        ))
        
        self.register(PatternConfig(
            name='SSH Private Key',
            pattern=r'-----BEGIN OPENSSH PRIVATE KEY-----',
            severity=self.CRITICAL,
            description='OpenSSH Private Key',
            reduce_severity_if_in_comment=False
        ))
        
        self.register(PatternConfig(
            name='PGP Private Key',
            pattern=r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            severity=self.CRITICAL,
            description='PGP Private Key',
            reduce_severity_if_in_comment=False
        ))
        
        self.register(PatternConfig(
            name='EC Private Key',
            pattern=r'-----BEGIN EC PRIVATE KEY-----',
            severity=self.CRITICAL,
            description='EC Private Key',
            reduce_severity_if_in_comment=False
        ))
        
        self.register(PatternConfig(
            name='JWT Token',
            pattern=r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+',
            severity=self.HIGH,
            description='JSON Web Token'
        ))
        
        self.register(PatternConfig(
            name='Bearer Token',
            pattern=r'[Bb]earer\s+[a-zA-Z0-9\-._~+/]+=*',
            severity=self.HIGH,
            description='Bearer Token'
        ))
        
        self.register(PatternConfig(
            name='Heroku API Key',
            pattern=r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
            severity=self.HIGH,
            description='Heroku API Key'
        ))
        
        self.register(PatternConfig(
            name='Azure Connection String',
            pattern=r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+',
            severity=self.CRITICAL,
            description='Azure Storage Connection String'
        ))
        
        self.register(PatternConfig(
            name='NPM Token',
            pattern=r'npm_[A-Za-z0-9]{36}',
            severity=self.HIGH,
            description='NPM Access Token'
        ))
        
        self.register(PatternConfig(
            name='PyPI Token',
            pattern=r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}',
            severity=self.HIGH,
            description='PyPI Upload Token'
        ))
        
        self.register(PatternConfig(
            name='Database Connection String',
            pattern=r'(mongodb|mysql|postgresql|postgres|redis):\/\/[^\s:]+:[^\s@]+@[^\s\/]+',
            severity=self.HIGH,
            description='Database Connection String with Credentials'
        ))
        
        self.register(PatternConfig(
            name='JDBC Connection String',
            pattern=r'jdbc:[^\s]+password=[^\s;]+',
            severity=self.HIGH,
            description='JDBC Connection String'
        ))
        
        self.register(PatternConfig(
            name='Generic API Key',
            pattern=r'[Aa][Pp][Ii][_\-\s]?[Kk][Ee][Yy][\'"\s]*[:=][\'"\s]*[0-9a-zA-Z]{32,45}',
            severity=self.HIGH,
            description='Generic API Key Pattern'
        ))
        
        self.register(PatternConfig(
            name='Generic Secret',
            pattern=r'[Ss][Ee][Cc][Rr][Ee][Tt][\'"\s]*[:=][\'"\s]*[0-9a-zA-Z]{32,45}',
            severity=self.HIGH,
            description='Generic Secret Pattern'
        ))
        
        self.register(PatternConfig(
            name='Generic Token',
            pattern=r'[Tt][Oo][Kk][Ee][Nn][\'"\s]*[:=][\'"\s]*[0-9a-zA-Z]{32,45}',
            severity=self.HIGH,
            description='Generic Token Pattern'
        ))
        
        self.register(PatternConfig(
            name='Password in Code',
            pattern=r'[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][\'"\s]*[:=][\'"\s]*[^\s\'\"]{8,}',
            severity=self.MEDIUM,
            description='Hardcoded Password'
        ))
        
        self.register(PatternConfig(
            name='Telegram Bot Token',
            pattern=r'[0-9]{8,10}:[A-Za-z0-9_-]{35}',
            severity=self.HIGH,
            description='Telegram Bot API Token'
        ))
        
        self.register(PatternConfig(
            name='Discord Bot Token',
            pattern=r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
            severity=self.HIGH,
            description='Discord Bot Token'
        ))
        
        self.register(PatternConfig(
            name='Docker Auth',
            pattern=r'"auth":\s*"[A-Za-z0-9+/=]{40,}"',
            severity=self.HIGH,
            description='Docker Registry Authentication'
        ))
        
        self.register(PatternConfig(
            name='Anthropic API Key',
            pattern=r'sk-ant-api\d{2}-[A-Za-z0-9_-]{80,}',
            severity=self.CRITICAL,
            description='Anthropic Claude API Key'
        ))

        self.register(PatternConfig(
            name='OpenAI API Key',
            pattern=r'sk-[A-Za-z0-9]{48}',
            severity=self.CRITICAL,
            description='OpenAI API Key'
        ))

        self.register(PatternConfig(
            name='Supabase Service Key',
            pattern=r'sbp_[a-f0-9]{40}',
            severity=self.CRITICAL,
            description='Supabase Service Role Key'
        ))

        self.register(PatternConfig(
            name='Vercel Token',
            pattern=r'vercel_[A-Za-z0-9]{24}',
            severity=self.HIGH,
            description='Vercel Deployment Token'
        ))

        self.register(PatternConfig(
            name='Linear API Key',
            pattern=r'lin_api_[A-Za-z0-9]{40}',
            severity=self.HIGH,
            description='Linear API Key'
        ))

        self.register(PatternConfig(
            name='Notion Integration Token',
            pattern=r'secret_[A-Za-z0-9]{43}',
            severity=self.HIGH,
            description='Notion Integration Token'
        ))

        self.register(PatternConfig(
            name='Datadog API Key',
            pattern=r'dd[a-z]{1}[0-9a-f]{32}',
            severity=self.HIGH,
            description='Datadog API Key'
        ))

        self.register(PatternConfig(
            name='Age Secret Key',
            pattern=r'AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}',
            severity=self.CRITICAL,
            description='Age Encryption Secret Key',
            reduce_severity_if_in_comment=False
        ))
    
    def register(self, pattern_config: PatternConfig):
        """Register a new pattern"""
        self._patterns[pattern_config.name] = pattern_config
        self._compiled_patterns[pattern_config.name] = pattern_config.compile()
    
    def unregister(self, pattern_name: str):
        """Remove a pattern from registry"""
        if pattern_name in self._patterns:
            del self._patterns[pattern_name]
            del self._compiled_patterns[pattern_name]
    
    def get_pattern(self, name: str) -> PatternConfig:
        """Get a pattern configuration by name"""
        return self._patterns.get(name)
    
    def get_all_patterns(self) -> Dict[str, PatternConfig]:
        """Get all registered patterns"""
        return self._patterns.copy()
    
    def get_compiled_patterns(self) -> Dict[str, re.Pattern]:
        """Get all compiled regex patterns"""
        return self._compiled_patterns.copy()
    
    def list_patterns(self) -> List[str]:
        """List all pattern names"""
        return list(self._patterns.keys())
    
    def get_patterns_by_severity(self, severity: str) -> Dict[str, PatternConfig]:
        """Get patterns filtered by severity"""
        return {
            name: config
            for name, config in self._patterns.items()
            if config.severity == severity
        }


class FileFilter:
    """File and path filtering"""
    
    SKIP_EXTENSIONS: Set[str] = {
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
        '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2', '.xz',
        '.mp3', '.mp4', '.avi', '.mov', '.wav', '.flac', '.mkv',
        '.exe', '.dll', '.so', '.dylib', '.bin',
        '.pyc', '.class', '.jar', '.war', '.ear',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.lock', '.sum', '.mod'
    }
    
    SKIP_PATHS: Set[str] = {
        'node_modules/', 'vendor/', '.git/', 'dist/', 'build/',
        'test/', 'tests/', '__pycache__/', '.pytest_cache/',
        'coverage/', '.coverage', 'venv/', 'env/', '.venv/',
        '.tox/', 'htmlcov/', '.eggs/', '*.egg-info/',
        'target/', 'bin/', 'obj/', '.gradle/',
        '.idea/', '.vscode/', '.vs/',
        'public/assets/', 'static/vendor/'
    }
    
    SKIP_FILENAMES: Set[str] = {
        'package-lock.json', 'yarn.lock', 'poetry.lock', 'Pipfile.lock',
        'go.sum', 'Cargo.lock', 'composer.lock', 'Gemfile.lock'
    }
    
    @classmethod
    def should_skip(cls, file_path: str) -> bool:
        """Check if file should be skipped"""
        if any(file_path.endswith(ext) for ext in cls.SKIP_EXTENSIONS):
            return True
        
        if any(skip_path in file_path for skip_path in cls.SKIP_PATHS):
            return True
        
        filename = file_path.split('/')[-1]
        if filename in cls.SKIP_FILENAMES:
            return True
        
        return False
    
    @classmethod
    def add_skip_extension(cls, extension: str):
        """Add a file extension to skip list"""
        if not extension.startswith('.'):
            extension = '.' + extension
        cls.SKIP_EXTENSIONS.add(extension)
    
    @classmethod
    def add_skip_path(cls, path: str):
        """Add a path pattern to skip list"""
        cls.SKIP_PATHS.add(path)

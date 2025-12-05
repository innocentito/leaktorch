from .scanner import SecretScanner
from .patterns import PatternRegistry, PatternConfig, FileFilter
from .finding import Finding
from .git_handler import GitHandler
from .gitignore_checker import GitIgnoreChecker
from .reporters import (
    Reporter,
    ConsoleReporter,
    JSONReporter,
    MarkdownReporter,
    CSVReporter,
    SummaryReporter,
    ReporterFactory
)

# NEW: Import logging
from .logger import logger, setup_logger

# NEW: Import exceptions
from .exceptions import (
    LeakTorchError,
    RepositoryError,
    ScanError,
    PatternError,
    ConfigError
)

# NEW: Import utilities (optional, but good to have)
from . import utils

# Version
__version__ = "1.0.0"

# Define what gets imported with "from leaktorch import *"
__all__ = [
    # Core classes
    'SecretScanner',
    'PatternRegistry',
    'PatternConfig',
    'FileFilter',
    'Finding',
    'GitHandler',
    'GitIgnoreChecker',
    
    # Reporters
    'Reporter',
    'ConsoleReporter',
    'JSONReporter',
    'MarkdownReporter',
    'CSVReporter',
    'SummaryReporter',
    'ReporterFactory',
    
    # NEW: Logging
    'logger',
    'setup_logger',
    
    # NEW: Exceptions
    'LeakTorchError',
    'RepositoryError',
    'ScanError',
    'PatternError',
    'ConfigError',
    
    # NEW: Utils module
    'utils',
    
    # Metadata
    '__version__',
]

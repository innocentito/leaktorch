# LeakTorch Summary

LeakTorch is a Python-based tool designed to scan Git repositories for accidentally committed secrets, such as API keys, tokens, and passwords. It provides a command-line interface and supports scanning both local and remote repositories, with options to skip git history for faster scans.

## Key Features
- Detects a wide range of secret types using regex-based patterns
- Scans code, git history, and respects .gitignore rules
- Supports multiple output formats (console, JSON, Markdown, CSV)
- Handles common false positives and allows pattern customization
- Modular design with extensible pattern and reporter systems

## Main Components
- **scanner.py**: Core scanning engine that detects secrets in code using defined patterns and filters out common false positives.
- **patterns.py**: Defines secret detection patterns and manages their configuration and severity.
- **reporters.py**: Handles formatting and output of scan results in various formats.
- **cli.py**: Command-line interface for running scans and configuring options.
- **git_handler.py**: Manages git operations for scanning repositories.
- **utils.py**: Utility functions for masking secrets, file checks, and more.
- **exceptions.py**: Custom exception classes for error handling.

## Usage Example
```sh
# Scan a local repository
leaktorch /path/to/repo

# Scan a remote repository
leaktorch https://github.com/user/repo

# Skip git history for a faster scan
leaktorch /path/to/repo --no-history
```

## Project Metadata
- Author: LeakTorch Contributors
- License: MIT
- Repository: https://github.com/leaktorch/leaktorch

---
*Generated on 2025-12-07*

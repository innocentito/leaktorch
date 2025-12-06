# LeakTorch 🔦

**A powerful Git repository secret scanner for detecting accidentally committed secrets**

LeakTorch helps you find API keys, tokens, passwords, and other sensitive information that may have been accidentally committed to your git repositories. It scans both current files and git history to ensure no secrets are lurking in your codebase.

## Features

✨ **Comprehensive Detection**
- 40+ built-in secret patterns (AWS keys, GitHub tokens, API keys, private keys, etc.)
- Entropy analysis for detecting unknown secret types
- Scans current files AND full git history

🎯 **Smart Scanning**
- Configurable severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- Intelligent file filtering (skips binaries, node_modules, etc.)
- Deduplication to avoid duplicate findings

🌐 **Flexible Input**
- Scan local repositories
- Scan remote repositories (GitHub, GitLab, Bitbucket)
- No need to clone repos manually

📊 **Multiple Output Formats**
- Colorized console output
- JSON export
- Markdown reports
- CSV export
- Summary reports

🔧 **Extensible Architecture**
- Easy to add custom secret patterns
- Modular design for easy customization
- Well-documented API for integration

## Installation

### From Source

```bash
git clone https://github.com/yourusername/leaktorch.git
cd leaktorch
pip install -r requirements.txt
```

### Using pip (when published)

```bash
pip install . -e
```

## Quick Start

### Basic Usage

```bash
# Scan a local repository
leaktorch /path/to/your/repo

# Scan a remote repository
leaktorch https://github.com/user/repo

# Skip git history for faster scanning
leaktorch /path/to/repo --no-history
```

### Export Reports

```bash
# Export to JSON
leaktorch /path/to/repo -o report.json

# Export to Markdown
leaktorch /path/to/repo -o report.md --format markdown

# Export to CSV
leaktorch /path/to/repo -o report.csv --format csv
```

### Advanced Options

```bash
# Verbose output with custom entropy threshold
leaktorch /path/to/repo -v --entropy 5.0

# Only show critical findings
leaktorch /path/to/repo --severity CRITICAL

# Quiet mode (minimal output)
leaktorch /path/to/repo --quiet -o report.json

# List all available detection patterns
leaktorch --list-patterns
```

## Detected Secret Types

LeakTorch detects 40+ types of secrets including:

### Cloud Providers
- AWS Access Keys & Secret Keys
- Azure Connection Strings
- Google API Keys & OAuth tokens
- Heroku API Keys

### Version Control
- GitHub Personal Access Tokens
- GitLab Personal Access Tokens
- Generic Git credentials

### Payment Services
- Stripe API Keys (Live & Test)
- PayPal/Braintree tokens

### Communication
- Slack Tokens & Webhooks
- Twilio API Keys
- SendGrid API Keys
- Mailgun API Keys
- Telegram Bot Tokens
- Discord Bot Tokens

### Databases
- MongoDB connection strings
- MySQL connection strings
- PostgreSQL connection strings
- JDBC connection strings

### Authentication
- JWT Tokens
- Bearer Tokens
- OAuth tokens

### Encryption Keys
- RSA Private Keys
- SSH Private Keys
- PGP Private Keys
- EC Private Keys

### Package Managers
- NPM Tokens
- PyPI Tokens

### Generic Patterns
- API Keys
- Secrets
- Tokens
- Passwords in code

## Project Structure

```
leaktorch/
├── leaktorch/
│   ├── __init__.py          # Package initialization
│   ├── scanner.py           # Core scanning engine
│   ├── patterns.py          # Secret pattern definitions
│   ├── finding.py           # Finding data structure
│   ├── git_handler.py       # Git operations
│   ├── reporters.py         # Output formatters
│   ├── utils.py             # Helper functions
│   └──cli.py                # CLI entry point
├── setup.py                 # Package setup
├── requirements.txt         # Dependencies
└── README.md               # This file
```

## API Usage

You can also use LeakTorch programmatically in your Python projects:

```python
from leaktorch import SecretScanner, PatternRegistry, ConsoleReporter

# Initialize scanner
scanner = SecretScanner(
    entropy_threshold=4.5,
    scan_history=True,
    verbose=True
)

# Scan a repository
findings = scanner.scan_repository('/path/to/repo')

# Get statistics
stats = scanner.get_statistics()

# Generate report
reporter = ConsoleReporter()
reporter.report(findings, stats)

# Export to JSON
from leaktorch import JSONReporter
json_reporter = JSONReporter()
json_reporter.save(findings, stats, 'report.json')
```

### Custom Patterns

Add your own secret patterns:

```python
from leaktorch import PatternRegistry, PatternConfig

registry = PatternRegistry()

# Add a custom pattern
registry.register(PatternConfig(
    name='My Custom API Key',
    pattern=r'myapi_[0-9a-f]{32}',
    severity='HIGH',
    description='Custom API key for my service'
))

# Use with scanner
scanner = SecretScanner(pattern_registry=registry)
```

## Configuration

### Entropy Threshold

The entropy threshold determines how random a string must be to be considered a potential secret. Higher values reduce false positives but may miss some secrets.

- Default: `4.5`
- Recommended range: `4.0` - `5.5`
- Lower values: More sensitive (more findings, more false positives)
- Higher values: Less sensitive (fewer findings, fewer false positives)

### File Filtering

LeakTorch automatically skips:
- Binary files (images, videos, executables)
- Package manager directories (node_modules, vendor)
- Build directories (dist, build, target)
- Lock files (package-lock.json, yarn.lock)

You can customize filtering:

```python
from leaktorch import FileFilter

# Add custom extensions to skip
FileFilter.add_skip_extension('.custom')

# Add custom paths to skip
FileFilter.add_skip_path('my-ignore-dir/')
```

## Exit Codes

LeakTorch uses exit codes to indicate scan results:

- `0`: No secrets found (success)
- `1`: Secrets detected (failure)
- `130`: Interrupted by user (Ctrl+C)

This makes it easy to integrate with CI/CD pipelines:

```bash
if python cli.py /path/to/repo; then
    echo "No secrets found!"
else
    echo "Secrets detected! Review findings."
    exit 1
fi
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Secret Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
        with:
          fetch-depth: 0  # Full history for scanning
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install LeakTorch
        run: |
          pip install gitpython colorama
          git clone https://github.com/yourusername/leaktorch.git
      
      - name: Scan for secrets
        run: python leaktorch/cli.py . -o report.json
      
      - name: Upload report
        if: failure()
        uses: actions/upload-artifact@v2
        with:
          name: secret-scan-report
          path: report.json
```

### GitLab CI

```yaml
secret_scan:
  stage: test
  image: python:3.9
  script:
    - pip install gitpython colorama
    - git clone https://github.com/yourusername/leaktorch.git
    - python leaktorch/cli.py . -o report.json
  artifacts:
    when: on_failure
    paths:
      - report.json
```

## Best Practices

1. **Scan regularly**: Integrate LeakTorch into your CI/CD pipeline
2. **Scan before pushing**: Run manual scan before pushing changes
3. **Review history**: Always scan with `--no-history` disabled initially
4. **Address findings immediately**: Rotate exposed credentials ASAP
5. **Use .gitignore**: Prevent sensitive files from being committed
6. **Environment variables**: Store secrets in environment variables, not code
7. **Secret management**: Use services like AWS Secrets Manager, HashiCorp Vault

## Performance Tips

- Use `--no-history` for quick scans of large repositories
- Adjust `--entropy` threshold based on your needs
- Use `--severity CRITICAL` to focus on the most important findings
- Scan specific paths instead of entire repositories when possible

## Contributing

Contributions are welcome! Here's how you can help:

1. **Add new patterns**: Submit PRs with new secret detection patterns
2. **Improve detection**: Enhance existing patterns to reduce false positives
3. **Report bugs**: Open issues for any bugs you find
4. **Documentation**: Help improve documentation and examples
5. **Features**: Suggest or implement new features



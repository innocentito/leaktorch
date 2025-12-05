"""
leaktorch/scanner.py
Core scanning engine for detecting secrets
"""

import re
import os
from typing import List, Set, Optional
from pathlib import Path

from .patterns import PatternRegistry, FileFilter
from .finding import Finding
from .git_handler import GitHandler
from .gitignore_checker import GitIgnoreChecker
from .utils import is_binary_file, mask_secret
from .logger import logger


class SecretScanner:
    """Main scanner for detecting secrets in code"""
    
    COMMON_FALSE_POSITIVES = {
        'AWS Access Key': ['AKIAIOSFODNN7EXAMPLE', 'AKIA0000000000000000', 'AKIAIOSFODNN7EXAMPLE1', 'AKIDEXAMPLE'],
        'GitHub Personal Access Token': ['ghp_1234567890123456789012345678901234', 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'],
        'JWT Token': ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'],
        'Generic API Key': ['your_api_key_here', 'YOUR_API_KEY', 'api_key_here', 'xxxxxxxxxxxxxxxxxxxxxxxxxxxx'],
        'Generic Secret': ['your_secret_here', 'YOUR_SECRET', 'secret_here'],
        'Generic Token': ['your_token_here', 'YOUR_TOKEN'],
        'Password in Code': ['password', 'changeme', 'Password123', 'your_password'],
    }
    
    FALSE_POSITIVE_WORDS = {'example', 'test', 'dummy', 'sample', 'placeholder', 'xxxxx', 'yyyyy', 'zzzzz', 'insert', 'replace'}
    
    def __init__(
        self,
        pattern_registry: Optional[PatternRegistry] = None,
        entropy_threshold: float = 4.5,
        scan_history: bool = True,
        verbose: bool = False,
        ignore_gitignored: bool = True,
        max_file_size: int = 1048576,
        whitelist_file: Optional[str] = None
    ):
        """
        Initialize the scanner
        
        Args:
            pattern_registry: Custom pattern registry (uses default if None)
            entropy_threshold: Minimum entropy for generic patterns
            scan_history: Whether to scan git history
            verbose: Enable verbose output
            ignore_gitignored: Whether to ignore files that are in .gitignore
            max_file_size: Maximum file size to scan in bytes
            whitelist_file: Path to whitelist file
        """
        self.pattern_registry = pattern_registry or PatternRegistry()
        self.entropy_threshold = entropy_threshold
        self.scan_history = scan_history
        self.verbose = verbose
        self.ignore_gitignored = ignore_gitignored
        self.max_file_size = max_file_size
        
        self.gitignore_checker: Optional[GitIgnoreChecker] = None
        self.whitelist_entries = []
        
        if whitelist_file and os.path.exists(whitelist_file):
            self._load_whitelist(whitelist_file)
        
        self.files_scanned = 0
        self.commits_scanned = 0
        self.findings: List[Finding] = []
        self._seen_findings: Set[Finding] = set()
        self.ignored_findings = 0
        self.whitelisted_findings = 0
        self.false_positives = 0
    
    def _load_whitelist(self, whitelist_file: str):
        """Load whitelist entries from file"""
        try:
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            entries_raw = content.split('---')
            for entry_text in entries_raw:
                entry_text = entry_text.strip()
                if not entry_text or entry_text.startswith('#'):
                    continue
                
                entry_data = {}
                for line in entry_text.split('\n'):
                    line = line.strip()
                    if ':' in line and not line.startswith('#'):
                        key, value = line.split(':', 1)
                        entry_data[key.strip()] = value.strip()
                
                if entry_data:
                    self.whitelist_entries.append(entry_data)
                    
            if self.verbose:
                logger.info(f"Loaded {len(self.whitelist_entries)} whitelist entries")
        except Exception as e:
            if self.verbose:
                logger.warning(f"Could not load whitelist: {e}")
    
    def _is_whitelisted(self, finding: Finding) -> bool:
        """Check if finding is whitelisted"""
        for entry in self.whitelist_entries:
            match = True
            
            if 'type' in entry and entry['type'] != finding.secret_type:
                match = False
            if 'file' in entry and entry['file'] != finding.file_path:
                match = False
            if 'line' in entry and int(entry['line']) != finding.line_number:
                match = False
            if 'match' in entry and entry['match'] != finding.matched_string:
                match = False
            
            if match:
                return True
        
        return False
    
    def _is_false_positive(self, secret_type: str, matched_string: str) -> bool:
        """Check if matched string is a known false positive"""
        fps = self.COMMON_FALSE_POSITIVES.get(secret_type, [])
        if matched_string in fps:
            return True
        
        matched_lower = matched_string.lower()
        for word in self.FALSE_POSITIVE_WORDS:
            if word in matched_lower:
                return True
        
        if len(set(matched_string)) <= 3:
            return True
        
        return False
    
    def _is_in_comment(self, line: str, file_path: str) -> bool:
        """Check if line is in a comment"""
        line_stripped = line.strip()
        file_ext = Path(file_path).suffix.lower()
        
        if file_ext == '.py':
            return line_stripped.startswith('#')
        elif file_ext in ['.js', '.ts', '.tsx', '.jsx', '.java', '.c', '.cpp', '.h', '.hpp', '.go', '.rs', '.swift', '.kt']:
            return line_stripped.startswith('//')
        elif file_ext in ['.html', '.xml', '.vue']:
            return '<!--' in line_stripped
        elif file_ext in ['.css', '.scss', '.sass']:
            return line_stripped.startswith('/*')
        elif file_ext == '.rb':
            return line_stripped.startswith('#')
        elif file_ext in ['.sh', '.bash', '.zsh']:
            return line_stripped.startswith('#')
        elif file_ext in ['.yaml', '.yml']:
            return line_stripped.startswith('#')
        
        return False
    
    def _is_test_file(self, file_path: str) -> bool:
        """Check if file is a test file"""
        test_indicators = [
            'test_', '_test.', 'test/', '/tests/', '/test/',
            'spec.', '.spec.', '__test__', '.test.',
            'testing/', '/testing/', 'fixtures/', '/fixtures/'
        ]
        file_lower = file_path.lower()
        return any(indicator in file_lower for indicator in test_indicators)
    
    def _adjust_severity(self, severity: str, context: dict, pattern_config) -> str:
        """Adjust severity based on context"""
        if not pattern_config:
            return severity
            
        severity_map = {
            'CRITICAL': 'HIGH',
            'HIGH': 'MEDIUM',
            'MEDIUM': 'LOW',
            'LOW': 'LOW'
        }
        
        if context.get('in_comment') and pattern_config.reduce_severity_if_in_comment:
            return severity_map.get(severity, severity)
        
        if context.get('is_test_file') and pattern_config.reduce_severity_if_in_test:
            return severity_map.get(severity, severity)
        
        return severity
    
    def scan_content(
        self,
        content: str,
        file_path: str,
        commit_hash: Optional[str] = None
    ) -> List[Finding]:
        """
        Scan content for secrets
        
        Args:
            content: File content to scan
            file_path: Path to the file
            commit_hash: Git commit hash (if scanning history)
        
        Returns:
            List of findings
        """
        findings = []
        lines = content.split('\n')
        compiled_patterns = self.pattern_registry.get_compiled_patterns()
        
        is_in_gitignore = False
        if commit_hash is None and self.gitignore_checker:
            is_in_gitignore = self.gitignore_checker.is_ignored(file_path)
        
        is_test = self._is_test_file(file_path)
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
            
            in_comment = self._is_in_comment(line, file_path)
            context = {'in_comment': in_comment, 'is_test_file': is_test}
            
            for pattern_name, compiled_pattern in compiled_patterns.items():
                pattern_config = self.pattern_registry.get_pattern(pattern_name)
                
                for match in compiled_pattern.finditer(line):
                    matched_text = match.group(0)
                    
                    if self._is_false_positive(pattern_name, matched_text):
                        self.false_positives += 1
                        continue
                    
                    if self._needs_entropy_check(pattern_name):
                        entropy = Finding.calculate_entropy(matched_text)
                        if entropy < self.entropy_threshold:
                            continue
                    
                    severity = self._adjust_severity(pattern_config.severity, context, pattern_config)
                    
                    finding = Finding(
                        secret_type=pattern_name,
                        matched_string=matched_text,
                        line_content=line,
                        line_number=line_num,
                        file_path=file_path,
                        severity=severity,
                        commit_hash=commit_hash,
                        is_in_gitignore=is_in_gitignore
                    )
                    
                    if self._is_whitelisted(finding):
                        if self.verbose:
                            logger.debug(f"Whitelisted: {pattern_name} in {file_path}:{line_num}")
                        self.whitelisted_findings += 1
                        continue
                    
                    if is_in_gitignore and self.ignore_gitignored:
                        if self.verbose:
                            logger.debug(f"Ignoring secret in .gitignore file: {file_path}")
                        self.ignored_findings += 1
                        continue
                    
                    if finding not in self._seen_findings:
                        self._seen_findings.add(finding)
                        findings.append(finding)
        
        return findings
    
    def _needs_entropy_check(self, pattern_name: str) -> bool:
        """Check if a pattern requires entropy validation"""
        entropy_check_patterns = [
            'Generic API Key',
            'Generic Secret',
            'Generic Token',
            'Password in Code'
        ]
        return any(p in pattern_name for p in entropy_check_patterns)
    
    def scan_file(self, file_path: Path, commit_hash: Optional[str] = None) -> List[Finding]:
        """
        Scan a single file
        
        Args:
            file_path: Path to the file
            commit_hash: Git commit hash (if scanning history)
        
        Returns:
            List of findings
        """
        if FileFilter.should_skip(str(file_path)):
            return []
        
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                if self.verbose:
                    logger.debug(f"Skipping large file: {file_path} ({file_size} bytes)")
                return []
        except OSError:
            return []
        
        if is_binary_file(str(file_path)):
            if self.verbose:
                logger.debug(f"Skipping binary file: {file_path}")
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            self.files_scanned += 1
            findings = self.scan_content(content, str(file_path), commit_hash)
            self.findings.extend(findings)
            
            return findings
            
        except Exception as e:
            if self.verbose:
                print(f"Error scanning {file_path}: {e}")
            return []
    
    def scan_repository(self, repo_path: str, is_remote: bool = False) -> List[Finding]:
        """
        Scan a git repository
        
        Args:
            repo_path: Path to repository or URL
            is_remote: Whether the repository is remote
        
        Returns:
            List of all findings
        """
        with GitHandler(repo_path, self.verbose) as git_handler:
            if is_remote:
                depth = None if self.scan_history else 1
                if not git_handler.clone_remote_repo(repo_path, depth):
                    return []
            else:
                if not git_handler.open_local_repo():
                    return []
            
            if not git_handler.is_valid_repo():
                print("Invalid repository")
                return []
            
            if not is_remote:
                self.gitignore_checker = GitIgnoreChecker(git_handler.repo_path)
                
                if self.verbose:
                    status = self.gitignore_checker.get_ignore_status()
                    if status['has_gitignore']:
                        print(f"Found .gitignore with {status['pattern_count']} patterns")
                    else:
                        print("⚠️  No .gitignore found - all secrets will be reported!")
            
            if self.verbose:
                print("Scanning current files...")
            
            for file_path in git_handler.get_current_files():
                rel_path = git_handler.get_relative_path(file_path)
                self.scan_file(file_path)
            
            if self.scan_history:
                if self.verbose:
                    print("Scanning git history...")
                
                for commit in git_handler.iter_commits():
                    self.commits_scanned += 1
                    
                    if self.verbose and self.commits_scanned % 10 == 0:
                        print(f"  Scanned {self.commits_scanned} commits...", end='\r')
                    
                    for file_path, content in git_handler.get_commit_files(commit):
                        if FileFilter.should_skip(file_path):
                            continue
                        
                        findings = self.scan_content(
                            content,
                            file_path,
                            commit.hexsha
                        )
                        self.findings.extend(findings)
                
                if self.verbose:
                    print()
        
        return self.findings
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get findings filtered by severity"""
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_file(self, file_path: str) -> List[Finding]:
        """Get findings for a specific file"""
        return [f for f in self.findings if f.file_path == file_path]
    
    def get_critical_findings(self) -> List[Finding]:
        """Get all critical findings"""
        return self.get_findings_by_severity('CRITICAL')
    
    def get_not_gitignored_findings(self) -> List[Finding]:
        """Get findings that are NOT in .gitignore (real problems)"""
        return [f for f in self.findings if not f.is_in_gitignore]
    
    def get_gitignored_findings(self) -> List[Finding]:
        """Get findings that ARE in .gitignore (less critical)"""
        return [f for f in self.findings if f.is_in_gitignore]
    
    def clear_findings(self):
        """Clear all findings and reset statistics"""
        self.findings.clear()
        self._seen_findings.clear()
        self.files_scanned = 0
        self.commits_scanned = 0
        self.ignored_findings = 0
        self.whitelisted_findings = 0
        self.false_positives = 0
    
    def get_statistics(self) -> dict:
        """Get scanning statistics"""
        severity_counts = {}
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        has_gitignore = self.gitignore_checker.has_gitignore if self.gitignore_checker else False
        not_in_gitignore = len([f for f in self.findings if not f.is_in_gitignore])
        in_gitignore = len([f for f in self.findings if f.is_in_gitignore])
        
        return {
            'files_scanned': self.files_scanned,
            'commits_scanned': self.commits_scanned,
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'has_gitignore': has_gitignore,
            'findings_not_in_gitignore': not_in_gitignore,
            'findings_in_gitignore': in_gitignore,
            'ignored_findings': self.ignored_findings,
            'whitelisted_findings': self.whitelisted_findings,
            'false_positives_filtered': self.false_positives
        }

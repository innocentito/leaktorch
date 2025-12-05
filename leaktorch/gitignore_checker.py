"""
leaktorch/gitignore_checker.py
Handle .gitignore file parsing and checking
"""

import os
from pathlib import Path
from typing import Set, Optional, List
import fnmatch


class GitIgnoreChecker:
    """Check if files match .gitignore patterns"""
    
    def __init__(self, repo_path: str):
        """
        Initialize GitIgnore checker
        
        Args:
            repo_path: Path to the repository root
        """
        self.repo_path = Path(repo_path)
        self.patterns: List[str] = []
        self.has_gitignore = False
        self._load_gitignore()
    
    def _load_gitignore(self):
        """Load and parse .gitignore file"""
        gitignore_path = self.repo_path / '.gitignore'
        
        if not gitignore_path.exists():
            return
        
        self.has_gitignore = True
        
        try:
            with open(gitignore_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Remove trailing spaces
                    line = line.rstrip()
                    
                    self.patterns.append(line)
        
        except Exception as e:
            print(f"Warning: Could not read .gitignore: {e}")
    
    def is_ignored(self, file_path: str) -> bool:
        """
        Check if a file path matches any .gitignore pattern
        
        Args:
            file_path: Path to check (relative to repo root)
        
        Returns:
            bool: True if file is in .gitignore
        """
        if not self.has_gitignore:
            return False
        
        # Convert to relative path if absolute
        try:
            if Path(file_path).is_absolute():
                file_path = str(Path(file_path).relative_to(self.repo_path))
        except ValueError:
            pass
        
        # Normalize path separators
        file_path = file_path.replace('\\', '/')
        
        for pattern in self.patterns:
            # Handle negation patterns (!)
            if pattern.startswith('!'):
                continue
            
            # Directory patterns (ending with /)
            if pattern.endswith('/'):
                if file_path.startswith(pattern) or f"{file_path}/".startswith(pattern):
                    return True
            
            # Exact match or wildcard match
            if fnmatch.fnmatch(file_path, pattern):
                return True
            
            # Match in any directory (pattern without /)
            if '/' not in pattern:
                filename = os.path.basename(file_path)
                if fnmatch.fnmatch(filename, pattern):
                    return True
            
            # Match with ** (recursive)
            if '**' in pattern:
                regex_pattern = pattern.replace('**/', '.*/')
                regex_pattern = regex_pattern.replace('**', '.*')
                import re
                if re.match(regex_pattern, file_path):
                    return True
        
        return False
    
    def get_ignore_status(self) -> dict:
        """
        Get information about .gitignore status
        
        Returns:
            dict: Status information
        """
        return {
            'has_gitignore': self.has_gitignore,
            'pattern_count': len(self.patterns),
            'gitignore_path': str(self.repo_path / '.gitignore')
        }

"""
leaktorch/git_handler.py
Git repository operations and history scanning
"""

import os
import tempfile
import shutil
from pathlib import Path
from typing import Generator, Tuple, Optional
from datetime import datetime
from git import Repo, GitCommandError, Commit
from .exceptions import RepositoryError
from .logger import logger


class GitHandler:
    """Handles all git-related operations"""
    
    def __init__(self, repo_path: str, verbose: bool = False):
        self.repo_path = repo_path
        self.verbose = verbose
        self.repo: Optional[Repo] = None
        self.is_temp = False
        self.temp_dir = None
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup temp directories"""
        self.cleanup()
    
    def open_local_repo(self) -> bool:
        """Open a local git repository"""
        try:
            self.repo = Repo(self.repo_path)
            return True
        except Exception as e:
            if self.verbose:
                print(f"Error opening repository: {e}")
            return False
    
    def clone_remote_repo(self, repo_url: str, depth: Optional[int] = None) -> bool:
        """
        Clone a remote repository
        
        Args:
            repo_url: URL of the remote repository
            depth: Limit clone depth (1 for shallow clone)
        
        Returns:
            bool: True if successful
        """
        try:
            self.temp_dir = tempfile.mkdtemp(prefix='leaktorch_')
            self.is_temp = True
            
            logger.info(f"Cloning repository: {repo_url}")
            
            self.repo = Repo.clone_from(repo_url, self.temp_dir, depth=depth)
            self.repo_path = self.temp_dir
            
            logger.info("Repository cloned successfully")
            return True
            
        except GitCommandError as e:
            logger.error(f"Failed to clone repository: {e}")
            raise RepositoryError(f"Could not clone {repo_url}") from e
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise RepositoryError(f"Unexpected error cloning {repo_url}") from e
    
    def cleanup(self):
        """Remove temporary directory if created"""
        if self.is_temp and self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                if self.verbose:
                    print(f"Cleaned up temporary directory: {self.temp_dir}")
            except Exception as e:
                if self.verbose:
                    print(f"Warning: Failed to cleanup temp directory: {e}")
    
    def get_current_files(self) -> Generator[Path, None, None]:
        """
        Generator that yields all files in the current working tree
        
        Yields:
            Path: File paths in the repository
        """
        if not self.repo:
            return
        
        for root, dirs, files in os.walk(self.repo_path):
            if '.git' in root:
                continue
            
            for file in files:
                file_path = Path(root) / file
                yield file_path
    
    def get_file_content(self, file_path: Path) -> Optional[str]:
        """
        Read content of a file
        
        Args:
            file_path: Path to the file
        
        Returns:
            str: File content or None if error
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            if self.verbose:
                print(f"Error reading {file_path}: {e}")
            return None
    
    def iter_commits(
        self,
        max_count: Optional[int] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        branch: Optional[str] = None
    ) -> Generator[Commit, None, None]:
        """
        Generator that yields commits in the repository
        
        Args:
            max_count: Maximum number of commits to return
            since: Only commits after this date (ISO format: '2024-01-01' or datetime)
            until: Only commits before this date (ISO format: '2024-12-31' or datetime)
            branch: Specific branch to scan (default: current branch)
        
        Yields:
            Commit: Git commit objects
        """
        if not self.repo:
            return
        
        try:
            kwargs = {}
            
            if max_count:
                kwargs['max_count'] = max_count
            
            if since:
                if isinstance(since, str):
                    since = datetime.fromisoformat(since)
                kwargs['since'] = since
            
            if until:
                if isinstance(until, str):
                    until = datetime.fromisoformat(until)
                kwargs['until'] = until
            
            if branch:
                kwargs['rev'] = branch
            
            for commit in self.repo.iter_commits(**kwargs):
                yield commit
                
        except Exception as e:
            if self.verbose:
                print(f"Error iterating commits: {e}")
    
    def get_commit_files(self, commit: Commit) -> Generator[Tuple[str, str], None, None]:
        """
        Generator that yields files and their content from a commit
        
        Args:
            commit: Git commit object
        
        Yields:
            Tuple[str, str]: (file_path, file_content)
        """
        try:
            for item in commit.tree.traverse():
                if item.type == 'blob':
                    try:
                        content = item.data_stream.read().decode('utf-8', errors='ignore')
                        yield (item.path, content)
                    except Exception:
                        pass
        except Exception as e:
            if self.verbose:
                print(f"Error reading commit {commit.hexsha[:8]}: {e}")
    
    def get_commit_count(self) -> int:
        """Get total number of commits in repository"""
        if not self.repo:
            return 0
        
        try:
            return sum(1 for _ in self.repo.iter_commits())
        except Exception:
            return 0
    
    def get_relative_path(self, file_path: Path) -> str:
        """
        Get relative path from repository root
        
        Args:
            file_path: Absolute file path
        
        Returns:
            str: Relative path from repo root
        """
        try:
            return str(file_path.relative_to(self.repo_path))
        except ValueError:
            return str(file_path)
    
    def is_valid_repo(self) -> bool:
        """Check if the opened repository is valid"""
        return self.repo is not None and not self.repo.bare
    
    def get_branches(self) -> list:
        """Get list of all branches in repository"""
        if not self.repo:
            return []
        
        try:
            return [branch.name for branch in self.repo.branches]
        except Exception:
            return []
    
    def get_current_branch(self) -> Optional[str]:
        """Get name of current branch"""
        if not self.repo:
            return None
        
        try:
            return self.repo.active_branch.name
        except Exception:
            return None
    
    @staticmethod
    def is_remote_url(path: str) -> bool:
        """
        Check if a path is a remote URL
        
        Args:
            path: Path or URL to check
        
        Returns:
            bool: True if it's a remote URL
        """
        return (
            path.startswith('http://') or
            path.startswith('https://') or
            path.startswith('git@') or
            path.startswith('ssh://')
        )

import math
from dataclasses import dataclass
from typing import Optional


@dataclass
class Finding:
    """Represents a detected secret in code"""
    
    secret_type: str
    matched_string: str
    line_content: str
    line_number: int
    file_path: str
    severity: str
    commit_hash: Optional[str] = None
    entropy: Optional[float] = None
    is_in_gitignore: bool = False  # NEW: Track if file is in .gitignore
    
    def __post_init__(self):
        """Calculate entropy after initialization"""
        if self.entropy is None:
            self.entropy = self.calculate_entropy(self.matched_string)
    
    @staticmethod
    def calculate_entropy(string: str) -> float:
        """
        Calculate Shannon entropy of a string
        Higher entropy indicates more randomness (typical of secrets)
        """
        if not string:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = float(string.count(chr(x))) / len(string)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy
    
    def to_dict(self) -> dict:
        """Convert finding to dictionary for serialization"""
        return {
            'type': self.secret_type,
            'severity': self.severity,
            'file': self.file_path,
            'line': self.line_number,
            'content': self.line_content.strip(),
            'matched': self.matched_string,
            'entropy': round(self.entropy, 2) if self.entropy else 0.0,
            'commit': self.commit_hash[:8] if self.commit_hash else None,
            'in_gitignore': self.is_in_gitignore  # NEW
        }
    
    def __str__(self) -> str:
        """String representation"""
        commit_info = f" (commit: {self.commit_hash[:8]})" if self.commit_hash else ""
        gitignore_info = " [IN .gitignore]" if self.is_in_gitignore else ""
        return (
            f"[{self.severity}] {self.secret_type}{gitignore_info}\n"
            f"  File: {self.file_path}:{self.line_number}{commit_info}\n"
            f"  Entropy: {self.entropy:.2f}"
        )
    
    def __eq__(self, other) -> bool:
        """Check equality (for deduplication)"""
        if not isinstance(other, Finding):
            return False
        return (
            self.secret_type == other.secret_type and
            self.file_path == other.file_path and
            self.line_number == other.line_number and
            self.matched_string == other.matched_string
        )
    
    def __hash__(self) -> int:
        """Hash for use in sets"""
        return hash((self.secret_type, self.file_path, self.line_number, self.matched_string))

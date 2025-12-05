"""
leaktorch/utils.py
Utility functions and helpers
"""

import os
from typing import List


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format
    
    Args:
        size_bytes: Size in bytes
    
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def is_binary_file(file_path: str) -> bool:
    """
    Check if a file is binary
    
    Args:
        file_path: Path to the file
    
    Returns:
        bool: True if file appears to be binary
    """
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(8192)
            
        # Check for null bytes (common in binary files)
        if b'\x00' in chunk:
            return True
        
        # Check if most bytes are printable
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
        non_text = sum(1 for byte in chunk if byte not in text_chars)
        
        return non_text / len(chunk) > 0.3 if chunk else False
        
    except Exception:
        return True


def validate_path(path: str) -> bool:
    """
    Validate if a path exists and is accessible
    
    Args:
        path: Path to validate
    
    Returns:
        bool: True if path exists and is readable
    """
    return os.path.exists(path) and os.access(path, os.R_OK)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing invalid characters
    
    Args:
        filename: Original filename
    
    Returns:
        Sanitized filename
    """
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename


def truncate_string(s: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate a string to maximum length
    
    Args:
        s: String to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
    
    Returns:
        Truncated string
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def get_file_extension(file_path: str) -> str:
    """
    Get file extension in lowercase
    
    Args:
        file_path: Path to file
    
    Returns:
        File extension (e.g., '.py')
    """
    _, ext = os.path.splitext(file_path)
    return ext.lower()


def deduplicate_findings(findings: List) -> List:
    """
    Remove duplicate findings
    
    Args:
        findings: List of Finding objects
    
    Returns:
        Deduplicated list
    """
    seen = set()
    unique_findings = []
    
    for finding in findings:
        # Create a unique key for each finding
        key = (
            finding.secret_type,
            finding.file_path,
            finding.line_number,
            finding.matched_string
        )
        
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    
    return unique_findings


def mask_secret(secret: str, visible_chars: int = 4) -> str:
    """
    Mask a secret string for safe display
    
    Args:
        secret: Secret string to mask
        visible_chars: Number of characters to leave visible at start/end
    
    Returns:
        Masked string
    """
    if len(secret) <= visible_chars * 2:
        return '*' * len(secret)
    
    return (
        secret[:visible_chars] + 
        '*' * (len(secret) - visible_chars * 2) + 
        secret[-visible_chars:]
    )

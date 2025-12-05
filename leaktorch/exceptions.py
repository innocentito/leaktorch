class LeakTorchError(Exception):
    """Base exception for all LeakTorch errors"""
    pass

class RepositoryError(LeakTorchError):
    """Error related to git repository operations"""
    pass

class ScanError(LeakTorchError):
    """Error during scanning process"""
    pass

class PatternError(LeakTorchError):
    """Error related to pattern configuration"""
    pass

class ConfigError(LeakTorchError):
    """Error in configuration"""
    pass

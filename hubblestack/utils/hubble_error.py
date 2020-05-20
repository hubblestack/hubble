"""
Error types for Nova-v2
"""

class AuditCheckVersionIncompatibleError(Exception):
    """
    Used when an audit check is skipped due to Hubble Version check
    """
    def __init__(self, message):
        super().__init__(message)

class AuditCheckFailedError(Exception):
    """
    Used when an audit check is failed
    """
    def __init__(self, message):
        super().__init__(message)

class AuditCheckValdiationError(Exception):
    """
    Used when an audit check is wrongly written or some mandatory params are not passed
    """
    def __init__(self, message):
        super().__init__(message)

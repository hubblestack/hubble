"""
Error types for Audit
"""

class HubbleCheckVersionIncompatibleError(Exception):
    """
    Used when an audit check is skipped due to Hubble Version check
    """
    def __init__(self, message):
        super().__init__(message)

class HubbleCheckFailedError(Exception):
    """
    Used when an audit check is failed
    """
    def __init__(self, message):
        super().__init__(message)

class HubbleCheckValidationError(Exception):
    """
    Used when an audit check is wrongly written or some mandatory params are not passed
    """
    def __init__(self, message):
        super().__init__(message)
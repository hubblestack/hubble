from hubblestack.extmods.module_runner.audit_runner import AuditRunner
from hubblestack.extmods.module_runner.fdg_runner import FdgRunner
from hubblestack.extmods.module_runner.runner import Caller

import logging
log = logging.getLogger(__name__)

def get_audit_runner():
    """
    Get instance of Audit runner
    """
    return AuditRunner()

def get_fdg_runner():
    """
    Get instance of FDG runner
    """
    return FdgRunner()

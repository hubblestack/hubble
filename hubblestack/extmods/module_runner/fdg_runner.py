from hubblestack.extmods.module_runner.runner import Runner
from hubblestack.extmods.module_runner.runner import Caller

import logging

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

class FdgRunner(Runner):
    """
    FDG runner
    """
    def __init__(self):
        super().__init__(Caller.FDG)


    def _validate_yaml_dictionary(self, yaml_dict):
        if 'main' not in yaml_dict:
            raise CommandExecutionError('FDG block must start with main block name : {0}'.format(yaml_dict))

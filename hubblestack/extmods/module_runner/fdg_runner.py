from hubblestack.extmods.module_runner.runner import Runner
from hubblestack.extmods.module_runner.runner import Caller
import hubblestack.extmods.module_runner.comparator

import logging

from salt.exceptions import CommandExecutionError
import salt.loader

log = logging.getLogger(__name__)
RETURNER_ID_BLOCK = None


class FdgRunner(Runner):
    """
    FDG runner
    """

    def __init__(self):
        super().__init__(Caller.FDG)

    def _validate_yaml_dictionary(self, yaml_dict):
        if 'main' not in yaml_dict:
            raise CommandExecutionError('FDG block must start with main block name : {0}'.format(yaml_dict))

    # overridden method
    def _execute(self, yaml_data_dict, fdg_file, args):
        starting_chained = args.get('starting_chained', None)

        global RETURNER_ID_BLOCK
        RETURNER_ID_BLOCK = (fdg_file, str(starting_chained))
        # Recursive execution of the blocks
        ret = self._fdg_execute('main', yaml_data_dict, chained=starting_chained)
        return RETURNER_ID_BLOCK, ret

    def _fdg_execute(self, block_id, block_data, chained=None, chained_status=True):
        """
        Recursive function which executes a block and any blocks chained by that
        block (by calling itself).
        """
        log.debug('Executing fdg block with id %s and chained value %s', block_id, chained)
        block = block_data.get(block_id)

        # preparing chained param
        chained_param = {"result": chained, "status": chained_status} if chained else None

        self._validate_module_params(block['module'], block_id, block, chaining_args=chained_param)

        # Status is used for the conditional chaining keywords
        status, ret = self._execute_module(
            block['module'], block_id, block, chaining_args=chained_param)

        log.debug('fdg execution "%s" returned %s', block_id, (status, ret))

        # handle if comparator is mentioned
        if 'comparator' in block:
            # override module status with comparator status
            status, ret = hubblestack.extmods.module_runner.comparator.run(
                block_id, block['comparator'], ret, status)

        if 'return' in block:
            returner = block['return']
        else:
            returner = None

        # get the result
        ret = ret if 'result' not in ret else ret['result']

        if 'xpipe_on_true' in block and status:
            log.debug('Piping via chaining keyword xpipe_on_true.')
            return self._xpipe(ret, status, block_data, block['xpipe_on_true'], returner)
        elif 'xpipe_on_false' in block and not status:
            log.debug('Piping via chaining keyword xpipe_on_false.')
            return self._xpipe(ret, status, block_data, block['xpipe_on_false'], returner)
        elif 'pipe_on_true' in block and status:
            log.debug('Piping via chaining keyword pipe_on_true.')
            return self._pipe(ret, status, block_data, block['pipe_on_true'], returner)
        elif 'pipe_on_false' in block and not status:
            log.debug('Piping via chaining keyword pipe_on_false.')
            return self._pipe(ret, status, block_data, block['pipe_on_false'], returner)
        elif 'xpipe' in block:
            log.debug('Piping via chaining keyword xpipe.')
            return self._xpipe(ret, status, block_data, block['xpipe'], returner)
        elif 'pipe' in block:
            log.debug('Piping via chaining keyword pipe.')
            return self._pipe(ret, status, block_data, block['pipe'], returner)
        else:
            log.debug('No valid chaining keyword matched. Returning.')
            if returner:
                self._return((ret, status), returner)
            return ret, status

    def _xpipe(self, chained, chained_status, block_data, block_id, returner=None):
        """
        Iterate over the given value and for each iteration, call the given fdg
        block by id with the iteration value as the passthrough.

        The results will be returned as a list.
        """
        ret = []
        for value in chained:
            ret.append(self._fdg_execute(block_id, block_data, value, chained_status))
        if returner:
            self._return(ret, returner)
        return ret

    def _pipe(self, chained, chained_status, block_data, block_id, returner=None):
        """
        Call the given fdg block by id with the given value as the passthrough and
        return the result
        """
        ret = self._fdg_execute(block_id, block_data, chained, chained_status)
        if returner:
            self._return(ret, returner)
        return ret

    def _return(self, data, returner):
        """
        Return data using the returner system
        """
        # JIT load the returners, since most returns will be handled by the daemon
        global __returners__
        if not __returners__:
            __returners__ = salt.loader.returners(__opts__, __salt__)

        returner += '.returner'
        if returner not in __returners__:
            log.error('Could not find %s returner.', returner)
            return False
        log.debug('Returning job data to %s', returner)
        returner_ret = {'id': __grains__['id'],
                        'jid': salt.utils.jid.gen_jid(__opts__),
                        'fun': 'fdg.fdg',
                        'fun_args': [],
                        'return': data[0],
                        'return_status': data[1]}
        __returners__[returner](returner_ret)
        return True

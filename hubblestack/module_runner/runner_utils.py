"""
An utility module for modules.
It has utility methods to prepare return results as well. So that, the result format will be same in all modules
"""

import logging

log = logging.getLogger(__name__)


def get_chained_param(chain_args):
    """
    Get the chained param, if present
    """
    if chain_args and 'chaining_args' in chain_args and chain_args.get('chaining_args') and 'result' in chain_args.get('chaining_args'):
        return chain_args.get('chaining_args').get('result')
    return None


def get_param_for_module(block_id, block_dict, param_name, default_value=None):
    """
    To get the parameter for a module.

    :param block_id:
        the block id
    :param block_dict:
        The dictionary for yaml block
    :param param_name:
        The name of param name to fetch from chaining or from dictionary
    :param default_value:
        The default value to be returned for the param
    """

    log.debug('Getting value for param name: {0}, for id: {1}'.format(param_name, block_id))
    if 'args' not in block_dict:
        return default_value

    if param_name in block_dict['args']:
        return block_dict['args'][param_name]

    return default_value


def prepare_negative_result_for_module(block_id, error_string):
    """
    A utility method which will format the error result to be returned from each module.
    Just pass the error string

    :param block_id:
        Id of the block
    :param error_string:
        Error string constant generated from module

    :return:
        A standard tuple result to be returned from each module
    """
    log.debug('Preparing error return result for id: {0}, error_string: {1}'.format(block_id, error_string))

    return False, {'error': error_string}


def prepare_positive_result_for_module(block_id, result):
    """
    A utility method which will format the positive result to be returned from each module.

    :param block_id:
        Id of the block
    :result:
        Actual value to be returned

    :return:
        A standard tuple result to be returned from each module
    """
    log.debug('Preparing return result for id: {0}'.format(block_id))

    return True, {'result': result}

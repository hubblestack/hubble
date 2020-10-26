# -*- encoding: utf-8 -*-
"""
A base class for Audit/FDG module runner. 

"""
import os
import logging
import yaml
from abc import ABC, abstractmethod
from packaging import version
import hubblestack.extmods.module_runner.comparator

import salt.loader
import salt.utils
from salt.exceptions import CommandExecutionError
from hubblestack.utils.hubble_error import HubbleCheckValidationError

log = logging.getLogger(__name__)
__hmods__ = {}
__comparator__ = {}


class Caller:
    """
    caller identification constant
    """
    AUDIT = 'AUDIT'
    FDG = 'FDG'


class Runner(ABC):
    """
    Runner class for Audit/FDG modules
    """

    def __init__(self, caller):
        super().__init__()
        # dictionary that will load modules
        self._caller = caller

    @abstractmethod
    def _validate_yaml_dictionary(self, yaml_dict):
        """
        An optional override method for derived classes.
        Giving a chance for implementation classes to validate the dictionary read from yaml
        """
        pass

    @abstractmethod
    def _execute(self, audit_data_dict, profile_file, args):
        pass

    def execute(self, file, args={}):
        """
        Starting method for execution of a profile file
        """
        log.info('Start executing profile {0}'.format(file))
        if not __hmods__:
            self.init_loader()

        # cache file
        cached_file = self._make_file_available(file)
        if not cached_file:
            raise CommandExecutionError('There was a problem caching the file: {0}'
                                        .format(file))

        # load yaml and validate
        yaml_data_dict = self._load_yaml(cached_file, file)
        self._validate_yaml_dictionary(yaml_data_dict)

        return self._execute(yaml_data_dict, file, args)

    def get_caller_name(self):
        return self._caller

    def init_loader(self):
        log.info('Initializing loader for hubble modules')
        global __hmods__
        __hmods__ = salt.loader.LazyLoader(salt.loader._module_dirs(__opts__, 'hubble_mods'),
                                           __opts__,
                                           tag='hubble_mods',
                                           pack={'__salt__': __salt__,
                                                 '__grains__': __grains__})

        # Comparator can be needed in both Audit/FDG
        global __comparator__
        __comparator__ = salt.loader.LazyLoader(salt.loader._module_dirs(__opts__, 'comparators'),
                                                __opts__,
                                                tag='comparators',
                                                pack={'__salt__': __salt__,
                                                      '__grains__': __grains__})
        hubblestack.extmods.module_runner.comparator.__comparator__ = __comparator__

    ######################################################
    ################# Non-Public methods #################
    ######################################################

    def _validate_module_params(self, module_name, profile_id, module_args, chaining_args=None):
        """
        A helper method to invoke module's validate_params method
        """
        if not module_args:
            raise CommandExecutionError('Could not execute block \'{0}\', as it is not found.'
                                        .format(profile_id))

        validate_param_method = '{0}.validate_params'.format(module_name)
        __hmods__[validate_param_method](profile_id, module_args, {'chaining_args': chaining_args,
                                                                   'caller': self._caller})

        # Comparators must exist in Audit
        if self._caller == Caller.AUDIT:
            if 'comparator' not in module_args:
                raise HubbleCheckValidationError('No mention of comparator in audit-id: {0}'.format(profile_id))
        elif self._caller == Caller.FDG:
            if 'module' not in module_args:
                raise CommandExecutionError('Could not execute block \'{0}\': no \'module\' found.'
                                            .format(profile_id))
            acceptable_block_args = {
                'return', 'module', 'args', 'comparator',
                'xpipe_on_true', 'xpipe_on_false', 'xpipe', 'pipe',
                'pipe_on_true', 'pipe_on_false',
            }
            for key in module_args:
                if key not in acceptable_block_args:
                    # Just doing error logging for unsupported tags
                    log.error('Could not execute block \'{0}\': '
                                                '\'{1}\' is not a valid block key'
                                                .format(profile_id, key))
            if 'args' not in module_args and 'comparator' not in module_args:
                raise CommandExecutionError('Could not execute block \'{0}\': '
                                            '\'{1}\' is not a valid block key'
                                            .format(profile_id, key))

    def _execute_module(self, module_name, profile_id, module_args, extra_args=None, chaining_args=None):
        """
        Helper method to execute a Module's execute() method.
        """
        execute_method = '{0}.execute'.format(module_name)
        return __hmods__[execute_method](profile_id, module_args, {'chaining_args': chaining_args,
                                                                   'extra_args': extra_args,
                                                                   'caller': self._caller})

    def _get_filtered_params_to_log(self, module_name, profile_id, module_args, extra_args=None, chaining_args=None):
        """
        Helper method to execute a Module's get_filtered_params_to_log() method.
        """
        filtered_log_method = '{0}.get_filtered_params_to_log'.format(module_name)
        return __hmods__[filtered_log_method](profile_id, module_args, {'chaining_args': chaining_args,
                                                                   'extra_args': extra_args,
                                                                   'caller': self._caller})

    def _make_file_available(self, file):
        """
        Cache file if path is salt://...
        """
        if file and file.startswith('salt://'):
            return __salt__['cp.cache_file'](file)
        return file

    def _load_yaml(self, filepath, filename):
        """
        Load and validate yaml file
        File must be a valid yaml file, and content loaded must form a python-dictionary

        Arguments:
            filepath {str} -- Actual filepath of profile file
            filename {str} -- Filename for logging purpose

        Returns:
            [dict] -- Dictionary representation for yaml
        """
        log.debug('Validating yaml file: %s', filename)
        # validating physical file existance
        if not filepath or not os.path.isfile(filepath):
            raise CommandExecutionError('Could not find file: {0}'.format(filepath))

        yaml_data = None
        try:
            with open(filepath, 'r') as file_handle:
                yaml_data = yaml.safe_load(file_handle)
        except Exception as exc:
            raise CommandExecutionError('Could not load yaml file: {0}, Exception: {1}'.format(filepath, exc))

        if not yaml_data or not isinstance(yaml_data, dict):
            raise CommandExecutionError('yaml data could not be loaded as dictionary: {0}'.format(filepath))

        return yaml_data

    def _is_hubble_version_compatible(self, profile_id, yaml_dictionary_data):
        """
        Function to check if current hubble version matches with provided values
        :param profile_id:
            the id of the block
        :param yaml_dictionary_data:
            The dictionary having data for a yaml block
        :return: boolean
            True if version is compatible with current version of hubble

        Provided values expect string with operators AND and OR.
        The precedence of AND is greater than OR and for a group of AND or OR, the order of evaluation is from left to right
        Following are the valid comparison operators:
        <,>,<=,>=,==,!=

        The version value after comparison operators should be fixed string. No regex is allowed in this version.
        If any character apart from the allowed values is passed to the provided values, then this function will throw the InvalidSyntax Error
        Some valid string types
            >3.0.0
            <=4.0.0
            >=2.0.0 OR != 4.1.2
            >=1.0.0 AND <=9.1.2 OR >=0.1.1 AND <=0.9.9
            >=2.0.0 AND >3.0.0 AND <=4.0.0 OR ==5.0.0
            >1.0 AND <10.0 AND >=2.0. OR >=4.0 AND <=5.0 OR ==6.0
            >1
        """
        log.debug("Current hubble version: %s" % __grains__['hubble_version'])
        current_version = version.parse(__grains__['hubble_version'])
        version_str = yaml_dictionary_data.get('hubble_version', '').strip()
        if not version_str:
            log.debug("No hubble version provided for check id: %s Thus returning true for this check" % (profile_id))
            return True
        if '*' in version_str:
            log.error("Invalid syntax in version condition. No regex is supported. check_id: %s hubble_version: %s" % (
            profile_id, version_str))
            return False
        version_str = version_str.upper()
        version_list = [[x.strip() for x in item.split("AND")] for item in version_str.split("OR")]
        # '>=2.0.0 AND >3.0.0 AND <=4.0.0 OR ==5.0.0' becomes [['>=2.0.0','>3.0.0','<=4.0.0'], ['==5.0.0']]
        for expression in version_list:  # Outer loop to evaluate OR conditions
            condition_match = True
            for condition in expression:  # Inner loop to evaluate AND conditions
                result = False
                if ' ' not in condition:
                    if condition.startswith('<='):
                        condition = condition[2:]
                        result = current_version <= version.parse(condition)
                    elif condition.startswith('>='):
                        condition = condition[2:]
                        result = current_version >= version.parse(condition)
                    elif condition.startswith('<'):
                        condition = condition[1:]
                        result = current_version < version.parse(condition)
                    elif condition.startswith('>'):
                        condition = condition[1:]
                        result = current_version > version.parse(condition)
                    elif condition.startswith('=='):
                        condition = condition[2:]
                        result = current_version == version.parse(condition)
                    elif condition.startswith('!='):
                        condition = condition[2:]
                        result = current_version != version.parse(condition)
                    else:
                        # Throw error as unexpected string occurs
                        log.error(
                            "Invalid syntax in version condition, check_id: %s condition: %s" % (profile_id, condition))
                else:
                    log.error(
                        "Invalid syntax in hubble version. No operator provided for check_id: %s condition: %s" % (
                        profile_id, condition))
                condition_match = condition_match and result
                if not condition_match:
                    # Found a false condition. No need to evaluate further for AND conditions
                    break
            if condition_match:
                # Found a true condition. No need to evaluate further for OR conditions
                return True
        return False

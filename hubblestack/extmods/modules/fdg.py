# -*- encoding: utf-8 -*-
'''
Flexible Data Gathering
=======================

This module is designed to allow security engineers more flexibility in their
data gathering, without allowing arbitrary command execution from
hubblestack_data. You can think of it like a read-only, sandboxed shell.

It uses yaml files from hubblestack_data, and allows special fdg modules to be
chained together using pipes.

Data might look something like this::

    main:
        return: splunk_nova_return
        module: module_name.function
        args:
            - foo
            - bar
        kwargs:
            arg1: blah
            arg2: blah
        pipe:
            unique_id

    unique_id:
        module: module_name.function
        args:
            - foo
            - bar
        kwargs:
            arg1: blah
            arg2: blah
        xpipe:
            unique_id2

    unique_id2:
        module: module_name.function:
        args:
            - foo
            - bar
        kwargs:
            arg1: test
            arg2: test

Each .yaml file contains a single fdg routine. ``main`` is a reserved id for
the entrypoint of the fdg routine. Chaining keywords such as ``pipe`` and
``xpipe`` both refer to other top-level ids in the file, and control the
execution control.

Here's a sample snippet with "names" for each of the parts::

    <id>:
        return: <returner_name>
        <module_name>.<function>:
            <keyword_arg_for_module>: <argument_value>
        <chaining_keyword>: <id>

In general, ``return`` should not be used, as returners can be handled in the
hubble scheduler. However, in some cases returners can be used within fdg
files. In this case, ``return`` is generally only be used on the ``main``
block, as you want to return the value when you're finished processing.
However, ``return`` can technically be used in any block, and when all chained
blocks under that block are done processing, the intermediate value will be
returned.

The ``<module_name>.<function>`` piece refers to fdg modules and the functions
within those modules. All public functions from fdg modules are available.

The fdg module functions must return a tuple of length two, with the first
value being the "status" of the run (which can be used by conditional chaining
keywords, see below) and the second value being the actual return value, which
will either be passed to chained blocks or returned back up the chain to the
calling block.

``<chaining_keywords>`` are the real flow control for the fdg routine. While
multiple chaining keywords can be used, only one will ever execute. Here is a
list of the supported chaining keywords, in order of precedence::

    pipe
    xpipe
    pipe_on_false
    pipe_on_true
    xpipe_on_false
    xpipe_on_true

Chaining keywords lower on the list take precedence over chaining keywords
higher on the list. Note that there are some exceptions -- for example,
chaining keywords ending in ``_on_true`` will only take precedence if the first
value returned from the module.function resolves to True in python.
``_on_false`` works similarly, though it works based on whether the value
resolves to False.  Otherwise it will be ignored, and the next precedence
chaining keyword will be executed.

You may have times where you want to use True/False conditionals to control
piping, but want to pass a value that's not restricted to True/False to the
the chained module. (Different lists, for example.) In this case, the module
should return a length-two tuple where the first value is the value to be used
for the conditional, and the second value is the value to be sent through the
chain.

``pipe`` chaining keywords send the whole value to the referenced fdg block.
The value is sent to the ``chained`` kwarg of the called module.function. All
public fdg module functions must accept this keyword arg.

``xpipe`` is similar to pipe, except that is expects an iterable value (usually
a list) and iterates over that value, calling the chained fdg block for each
value in the iteration. The results are put in a list, which is then returned.
The ``chained`` kwarg of the called module.function is the destination for
these ``xpipe`` values, same as with the ``pipe`` chaining keywords.

If there are no chaining keywords that are valid to execute, the fdg execution
will end and any ``return`` keywords will be evaluated as we move back up the
call chain.
'''
from __future__ import absolute_import
import logging
import salt.loader
import salt.utils

log = logging.getLogger(__name__)
__fdg__ = None
__returners__ = None


def fdg(fdg_file):
    '''
    Given an fdg file (usually a salt:// file, but can also be the absolute
    path to a file on the system), execute that fdg file, starting with the
    ``main`` block
    '''
    if fdg_file and fdg_file.startswith('salt://'):
        cached = __salt__['cp.cache_file'](fdg_file)
    else:
        cached = fdg_file
    if not cached:
        raise CommandExecutionError('There was a problem caching the fdg_file: {0}'
                                    .format(fdg_file))

    try:
        with open(cached) as handle:
            block_data = yaml.safe_load(handle)
    except Exception as exc:
        raise CommandExecutionError('Could not load fdg_file: {0}'.format(e))

    if not isinstance(block_data, dict):
        raise CommandExecutionError('fdg block_data not formed as a dict: {0}'.format(block_data))
    elif 'main' not in block_data:
        raise CommandExecutionError('fdg block_data : {0}'.format(block_data))

    # TODO instantiate fdg modules
    global __fdg__
    __fdg__ = {}

    # Recursive execution of the blocks
    _, ret = _fdg_execute('main', block_data)
    return ret


def _fdg_execute(block_id, block_data, chained=None):
    '''
    Recursive function which executes a block and any blocks chained by that
    block (by calling itself).
    '''
    block = block_data.get(block_id)
    if not block:
        raise CommandExecutionError('Could not execute block \'{0}\', as it is not found.'
                                    .format(block_id))
    if 'module' not in block:
        raise CommandExecutionError('Could not execute block \'{0}\': no \'module\' found.'
                                    .format(block_id))

    # Status is used for the conditional chaining keywords
    status, ret = __fdg__[block['module']](*block.get('args', []), chained=chained, **block.get('kwargs', {}))

    if 'return' in block:
        returner = block['return']
    else:
        returner = None

    if 'xpipe_on_true' in block and status:
        return _xpipe(ret, block_data, block['xpipe_on_true'], returner)
    elif 'xpipe_on_false' in block and not status:
        return _xpipe(ret, block_data, block['xpipe_on_false'], returner)
    elif 'pipe_on_true' in block and status:
        return _pipe(ret, block_data, block['pipe_on_true'], returner)
    elif 'pipe_on_false' in block and not status:
        return _pipe(ret, block_data, block['pipe_on_false'], returner)
    elif 'xpipe' in block:
        return _xpipe(ret, block_data, block['xpipe'], returner)
    elif 'pipe' in block:
        return _pipe(ret, block_data, block['pipe'], returner)
    else:
        if returner:
            _return(ret, returner)
        return ret


def _xpipe(chained, block_data, block_id, returner=None):
    '''
    Iterate over the given value and for each iteration, call the given fdg
    block by id with the iteration value as the passthrough.

    The results will be returned as a list.
    '''
    ret = []
    for value in chained:
        ret.append(_fdg_execute(block_id, block_data, chained))
    if returner:
        _return(ret, returner)
    return ret


def _pipe(chained, block_data, block_id, returner=None):
    '''
    Call the given fdg block by id with the given value as the passthrough and
    return the result
    '''
    ret = _fdg_execute(block_id, block_data, chained)
    if returner:
        _return(ret, returner)
    return ret


def _return(data, returner, returner_retry=None):
    '''
    Return data using the returner system
    '''
    # JIT load the returners, since most returns will be handled by the daemon
    global __returners__
    if not __returners__:
        __returners__ = salt.loader.returners(__opts__, __salt__)
    if returner_retry is None:
        returner_retry = __opts__.get(returner_retry, False)

    returner += '.returner'
    if returner not in __returners__:
        log.error('Could not find {0} returner.'.format(returner))
        continue
    log.debug('Returning job data to {0}'.format(returner))
    returner_ret = {'id': __grains__['id'],
                    'jid': salt.utils.jid.gen_jid(__opts__),
                    'fun': 'fdg.fdg',
                    'fun_args': [],
                    'return': data,
                    'retry': returner_retry}
    __returners__[returner](returner_ret)

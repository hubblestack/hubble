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
        module_name.function:
            arg1: blah
            arg2: blah
        pipe:
            unique_id

    unique_id:
        module_name.function:
            arg1: test
            arg2: test
            *args:
                - arg1
                - arg2
        xpipe:
            unique_id2

    unique_id2:
        module_name.function:
            arg1: test
            arg2: test
            *args:
                - arg1
                - arg2

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

In general, ``return`` should only be used on the ``main`` block, as you want
to return the value when you're finished processing. However, ``return`` can
technically be used in any block, and when all chained blocks under that block
are done processing, the intermediate value will be returned.

The ``<module_name>.<function>`` piece refers to fdg modules and the functions
within those modules. All public functions from fdg modules are available.

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
chaining keywords ending in ``_on_true`` will only take precedence if the value
returned from the module.function resolves to True in python. ``_on_false``
works similarly, though it works based on whether the value resolves to False.
Otherwise it will be ignored, and the next precedence chaining keyword will be
executed.

You may have times where you want to use True/False conditionals to control
piping, but want to pass a value that's not restricted to True/False to the
the chained module. (Different lists, for example.) In this case, the module
should return a length-two tuple where the first value is the value to be used
for the conditional, and the second value is the value to be sent through the
chain.

``pipe`` chaining keywords send the whole value to the referenced fdg block.
The value is sent to the ``chained`` kwarg of the called module.function. All
public fgd module functions must accept this keyword arg.

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

log = logging.getLogger(__name__)

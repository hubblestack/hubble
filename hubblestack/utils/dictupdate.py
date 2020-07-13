# -*- coding: utf-8 -*-
'''
Alex Martelli's soulution for recursive dict update from
http://stackoverflow.com/a/3233356
'''

try:
    from collections.abc import Mapping
except ImportError:
    from collections import Mapping

# Import 3rd-party libs
import copy
import logging

log = logging.getLogger(__name__)


def update(dest, upd, recursive_update=True, merge_lists=False):
    '''
    Recursive version of the default dict.update

    Merges upd recursively into dest

    If recursive_update=False, will use the classic dict.update, or fall back
    on a manual merge (helpful for non-dict types like FunctionWrapper)

    If merge_lists=True, will aggregate list object types instead of replace.
    The list in ``upd`` is added to the list in ``dest``, so the resulting list
    is ``dest[key] + upd[key]``. This behavior is only activated when
    recursive_update=True. By default merge_lists=False.

    .. versionchanged: 2016.11.6
        When merging lists, duplicate values are removed. Values already
        present in the ``dest`` list are not added from the ``upd`` list.
    '''
    if (not isinstance(dest, Mapping)) \
            or (not isinstance(upd, Mapping)):
        raise TypeError('Cannot update using non-dict types in dictupdate.update()')
    updkeys = list(upd.keys())
    if not set(list(dest.keys())) & set(updkeys):
        recursive_update = False
    if recursive_update:
        for key in updkeys:
            val = upd[key]
            try:
                dest_subkey = dest.get(key, None)
            except AttributeError:
                dest_subkey = None
            if isinstance(dest_subkey, Mapping) \
                    and isinstance(val, Mapping):
                ret = update(dest_subkey, val, merge_lists=merge_lists)
                dest[key] = ret
            elif isinstance(dest_subkey, list) \
                     and isinstance(val, list):
                if merge_lists:
                    merged = copy.deepcopy(dest_subkey)
                    merged.extend([x for x in val if x not in merged])
                    dest[key] = merged
                else:
                    dest[key] = upd[key]
            else:
                dest[key] = upd[key]
        return dest
    else:
        try:
            for k in upd:
                dest[k] = upd[k]
        except AttributeError:
            # this mapping is not a dict
            for k in upd:
                dest[k] = upd[k]
        return dest


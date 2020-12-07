# -*- coding: utf-8 -*-
'''
Return config information
'''

from hubblestack.utils.data import traverse_dict_and_list

def items():
    return __opts__

def get(key, default='', delimiter=':'):
    ret = traverse_dict_and_list(__opts__, key, '_|-', delimiter=delimiter)
    if ret != '_|-':
        return ret
    return default

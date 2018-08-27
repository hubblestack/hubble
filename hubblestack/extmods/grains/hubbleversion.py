# -*- coding: utf-8 -*-
'''
Add the hubble version to the grains
'''
import logging

from hubblestack import __version__

log = logging.getLogger(__name__)


def hubble_version():
    '''
    Add the hubble version to the grains
    '''
    return {'hubble_version': __version__}

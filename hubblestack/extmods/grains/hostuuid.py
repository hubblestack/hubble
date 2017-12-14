# -*- coding: utf-8 -*-
'''
Generate a unique uuid for this host, storing it on disk so it persists across
restarts
'''
import logging
import os
import uuid

log = logging.get_logger(__name__)


def host_uuid():
    '''
    Generate a unique uuid for this host, storing it on disk so it persists
    across restarts
    '''
    cached_uuid = os.path.join(os.path.dirname(__opts__['configfile']), 'hubble_cached_uuid')
    try:
        if os.path.isfile(cached_uuid):
            with open(cached_uuid, 'r') as f:
                return {'host_uuid': f.read()}
    except Exception as exc:
        log.exception('Problem retrieving cached host uuid')
    generated = uuid.uuid4()
    with open(cached_uuid, 'w') as f:
        f.write(cached_uuid)
    return {'host_uuid': generated}

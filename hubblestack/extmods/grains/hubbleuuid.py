# -*- coding: utf-8 -*-
"""
Generate a unique uuid for this host, storing it on disk so it persists across
restarts
"""
import logging
import os
import uuid

LOG = logging.getLogger(__name__)


def hubble_uuid():
    """
    Generate a unique uuid for this host, storing it on disk so it persists
    across restarts
    """
    cached_uuid_path = os.path.join(os.path.dirname(__opts__['configfile']), 'hubble_cached_uuid')
    existing_uuid = __opts__.get('hubble_uuid', None)
    try:
        if os.path.isfile(cached_uuid_path):
            with open(cached_uuid_path, 'r') as uuid_file:
                cached_uuid = uuid_file.read()
                # Check if it's changed out from under us -- problem!
                if existing_uuid and cached_uuid != existing_uuid:
                    LOG.error('hubble_uuid changed on disk unexpectedly!'
                              '\nPrevious: %s\nNew: %s\nKeeping previous.',
                              existing_uuid, cached_uuid)
                    # Write the previous UUID to the cache file
                    try:
                        with open(cached_uuid_path, 'w') as cache_file:
                            cache_file.write(existing_uuid)
                    except Exception:
                        LOG.exception('Problem writing cached hubble uuid to file: %s',
                                      cached_uuid_path)
                    return {'hubble_uuid': existing_uuid}
                return {'hubble_uuid': cached_uuid}
        elif existing_uuid:
            LOG.error('hubble_uuid was previously generated, but the cached '
                      'file is no longer present: %s', cached_uuid_path)
        else:
            LOG.warning('generating fresh uuid, no cache file found. '
                        '(probably not a problem)')
    except Exception:
        LOG.exception('Problem retrieving cached hubble uuid from file: %s', cached_uuid_path)

    # Generate a fresh one if needed
    if not existing_uuid:
        existing_uuid = str(uuid.uuid4())

    # Cache the new (or old if it needs re-caching) uuid
    try:
        with open(cached_uuid_path, 'w') as uuid_file:
            uuid_file.write(existing_uuid)
    except Exception:
        LOG.exception('Problem writing cached hubble uuid to file: %s', cached_uuid_path)

    return {'hubble_uuid': existing_uuid}

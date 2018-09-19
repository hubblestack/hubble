# -*- coding: utf-8 -*-
'''
Module for handling timeouts in code that may not be designed for it.
'''

import logging
log = logging.getLogger('hangtime')

import stopit

def hangtime_wrapper(**ht_kw):
    ''' stopit has a wrapper for this sort of thing
        but in the interests of being able to customize its behavior for hubble purposes
        ... here's a wrapper of our own

        Note that the linux itimers/signals/SIGALRM method of timeouts was a
        heckuvalot more time accurate. the timeout here is more like a loose
        suggestions than an actual timeout in the sense that timeout=600s is
        really more like 600±20s -- this is noted in the stopit docs too.
    '''
    callback = ht_kw.get('callback', None)
    timeout = ht_kw.get('timeout', 90)
    tag = ht_kw.get('tag', 'unknown')
    def _decorator(actual):
        def _decoration_wrapper(*a, **kw):
            try:
                with stopit.ThreadingTimeout(timeout) as to_ctx_mgr:
                    assert to_ctx_mgr.state == to_ctx_mgr.EXECUTING
                    return actual(*a, **kw)
            except stopit.TimeoutException as e:
                res = False
                if callback:
                    try: res = callback(tag)
                    except: pass
                if not res:
                    log.error("timeout(%s) during execution of %s", tag, actual)
        return _decoration_wrapper
    return _decorator

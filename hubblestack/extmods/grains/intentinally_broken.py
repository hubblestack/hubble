import time
import logging

log = logging.getLogger('intentionally_broken')

def intentionally_broken():
    for i in range(90):
        if i%5 == 0:
            log.debug("i=%d", i)
        time.sleep(1)
    return {'did_you_miss_me': True}

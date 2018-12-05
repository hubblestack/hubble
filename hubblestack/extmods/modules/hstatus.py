
import hubble.status

__virtualname__ = 'hstatus'

def __virtual__():
    return True

def get():
    ''' return the counters and timing status tracked by hubble.status

        (probably only useful from other excution modules)
    '''
    return hubble.status.HubbleStatus.as_json()

def dump():
    ''' trigger a dump to the status.json file as described in hubble.status

        This is intended to be invoked from a daemon schedule and is probably
        not useful outside that context.
    '''
    return hubble.status.HubbleStatus.dumpster_fire()

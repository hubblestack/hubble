
import hubblestack.status

__virtualname__ = 'hstatus'

def __virtual__():
    return True

def get():
    ''' return the counters and timing status tracked by hubblestack.status

        (probably only useful from other excution modules)
    '''
    return hubblestack.status.HubbleStatus.as_json()

def dump():
    ''' trigger a dump to the status.json file as described in hubblestack.status

        This is intended to be invoked from a daemon schedule and is probably
        not useful outside that context.
    '''
    return hubblestack.status.HubbleStatus.dumpster_fire()

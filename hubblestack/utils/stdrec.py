# -*- encoding: utf-8 -*-
"""
This is intended to generate data for splunk returners in a standard way.
Currently each returner seems to generate these data by hand in their own way.
This is being tested/used in the generic returner and probably only from
hstatus exec module (for now).
"""
import socket


def std_info():
    """ Generate and return hubble standard host data for use in events:
          minion_id, dest_host, dest_ip, dest_fqdn and system_uuid
    """
    minion_id = __opts__['id']
    local_fqdn = __grains__.get('local_fqdn', __grains__['fqdn'])

    ret = {
        'minion_id': minion_id,
        'dest_host': get_fqdn(),
        'dest_ip': get_fqdn_ip4(),
        'dest_fqdn': local_fqdn,
        'system_uuid': __grains__.get('system_uuid')
    }

    ret.update(__grains__.get('cloud_details', {}))

    return ret


def get_fqdn():
    """
    Do lots of error checking and get as close to a useable fqdn as possible
    """
    minion_id = __opts__['id']
    local_fqdn = __grains__.get('local_fqdn', __grains__['fqdn'])

    ret = {
        'minion_id': minion_id,
        'dest_host': get_fqdn(),
        'dest_ip': get_fqdn_ip4(),
        'dest_fqdn': local_fqdn,
        'system_uuid': __grains__.get('system_uuid')
    }

    ret.update(__grains__.get('cloud_details', {}))

    return ret


def get_fqdn():
    """
    Do lots of error checking and get as close to a useable fqdn as possible
    """
    minion_id = __opts__['id']
    fqdn = __grains__['fqdn']
    fqdn = fqdn if fqdn else minion_id

    # Sometimes fqdn reports a value of localhost. If that happens, try another method.
    bad_fqdns = ['localhost', 'localhost.localdomain', 'localhost6.localdomain6']
    if fqdn in bad_fqdns:
        new_fqdn = socket.gethostname()
        if '.' not in new_fqdn or new_fqdn in bad_fqdns:
            new_fqdn = get_fqdn_ip4()
        fqdn = new_fqdn

    return fqdn


def get_fqdn_ip4():
    """
    Get the first non-127.0* address as the fqdn ip
    """
    try:
        fqdn_ip4 = __grains__.get('local_ip4')
        if not fqdn_ip4:
            fqdn_ip4 = __grains__['fqdn_ip4'][0]
    except IndexError:
        try:
            fqdn_ip4 = __grains__['ipv4'][0]
        except IndexError:
            raise Exception('No ipv4 grains found. Is net-tools installed?')
    if fqdn_ip4.startswith('127.'):
        for ip4_addr in __grains__['ipv4']:
            if ip4_addr and not ip4_addr.startswith('127.'):
                fqdn_ip4 = ip4_addr
                break

    return fqdn_ip4


def index_extracted(payload):
    """ generate index extracted fields dictionary from the given payload based
    on the options in the config file """
    if not isinstance(payload.get('event'), dict):
        return
    index_extracted_fields = []
    try:
        index_extracted_fields.extend(__opts__.get('splunk_index_extracted_fields', []))
    except TypeError:
        pass

    fields = {}
    for item in index_extracted_fields:
        if item in payload['event']:
            val = payload['event'][item]
            if not isinstance(val, (list, dict, tuple)):
                fields["meta_%s" % item] = str(val)
    return fields


def update_payload(payload):
    """ update the given payload with index extracted fields (if applicable)
    and append std host data to the event (iff it's a dictionary) """
    if 'event' not in payload:
        payload['event'] = dict()
    if isinstance(payload['event'], dict):
        payload['event'].update(std_info())
    if not payload.get('host'):
        payload['host'] = get_fqdn()
    fields = index_extracted(payload)
    if fields:
        payload['fields'] = fields

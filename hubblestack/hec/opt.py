# -*- encoding: utf-8 -*-

# NOTE: this module receives __salt__, __grains__, etc from daemon.py during refresh_grains

# there's a lot of support below for things like this:
#   get_splunk_options('hubblestack:returner:splunk', 'hubblestack:nebula:returner:splunk')
#
# which looks in 'hubblestack:nebula:returner:splunk' iff nothing is found in 'hubblestack:returner:splunk'
#
# and support for things like this:
#   get_splunk_options('hubblestack:returner:splunk', some_default='something')
#
# which adds some_default to the default values
#
# but if nothing else is specified,
#   list_of_opts = get_splunk_options()
#
# we just look in [config.get]('hubblestack:returner:splunk')

import copy

class Required(object):
    pass
REQUIRED = Required()
del Required

MODALITIES = ('config.get',) # used to house grains.get before config.get

def _get_splunk_options(space, modality, **kw):
    ret = list()

    base_opts = {
        'token': REQUIRED,
        'indexer': REQUIRED,
        'index': REQUIRED,
        'port': '8088',
        'custom_fields': [],
        'sourcetype': 'hubble_log',
        'http_event_server_ssl': True,
        'proxy': {},
        'timeout': 9.05,
        'index_extracted_fields': [],
        'http_event_collector_ssl_verify': True,
    }

    nicknames = {
        'hec_ssl': 'http_event_server_ssl',
        'sourcetype_log': 'sourcetype',
    }

    n = kw.pop('_nick', {})
    base_opts.update(kw)
    nicknames.update(n)

    req = [ k for k in base_opts if base_opts[k] is REQUIRED ]

    sfr = __salt__[modality](space)
    if sfr:
        if not isinstance(sfr, list):
            sfr = [sfr]
        for opt in sfr:
            final_opts = base_opts.copy()
            for k in opt:
                j = nicknames.get(k, k)
                if j in final_opts:
                    final_opts[j] = opt[k]
            if REQUIRED in final_opts.values():
                raise Exception('{0} must be specified in the {1} configs!'.format(req, space))
            ret.append(final_opts)

    return ret

def get_splunk_options(*spaces, **kw):
    if not spaces:
        spaces = ['hubblestack:returner:splunk']

    for space in spaces:
        for modality in MODALITIES:
            ret = _get_splunk_options(space, modality, **copy.deepcopy(kw))
            if ret:
                return ret

    return []

def __setup_for_testing():
    global __salt__, __opts__
    import hubblestack.daemon
    parsed_args = hubblestack.daemon.parse_args()
    import salt.config
    parsed_args['configfile'] = config_file = '/etc/hubble/hubble'
    __opts__ = salt.config.minion_config(config_file)
    __opts__['conf_file'] = config_file
    __opts__.update(parsed_args)
    import salt.loader
    __grains__ = salt.loader.grains(__opts__)
    __utils__ = salt.loader.utils(__opts__)
    __salt__ = salt.loader.minion_mods(__opts__, utils=__utils__)

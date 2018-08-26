
# NOTE: this module receives __salt__, __grains__, etc from daemon.py during refresh_grains

class Required(object):
    pass
REQUIRED = Required()
del Required

def get_splunk_options(space, **kw):
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

    for sf in ('config.get', 'grains.get'):
        sfr = __salt__[sf](space)
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

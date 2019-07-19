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
#
# Additionally, the defaults for disk_queue, disk_queue_size and
# disk_queue_compression can be set in the top level configuration -- although,
# are still overridden by per-hec configs.


import copy

class Required(object):
    pass
REQUIRED = Required()
del Required

MODALITIES = ('grains.get','config.get',) # search in grains first, fallback to config.get

def _get_splunk_options(space, modality, **kw):
    ret = list()

    confg = __salt__['config.get']

    base_opts = {
        'token': REQUIRED,
        'indexer': REQUIRED,
        'index': REQUIRED,
        'port': '8088',
        'custom_fields': [],
        'sourcetype': 'hubble_log',
        'http_event_server_ssl': True,
        'proxy': None,
        'timeout': 9.05,
        'index_extracted_fields': [],
        'http_event_collector_ssl_verify': True,
        'add_query_to_sourcetype': True,
        # disk_queue* can come from the top of the config
        'disk_queue': confg('disk_queue', False),
        'disk_queue_size': confg('disk_queue_size', 100 * (1024 ** 2)),
        'disk_queue_compression': confg('disk_queue_compression', 5),
    }

    nicknames = kw.pop('_nick', {'sourcetype_log': 'sourcetype'})
    base_opts.update(kw)

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
    """
    params:
      *spaces: non-keyword arguments are config namespaces to search
               the default is 'hubblestack:returner:splunk' (if nothing else is specified)
      **kw: All keyword arguments are added to the optionspace as defaults that can be replaced by configs.
            The exception is a special keyword argument '_nick', which remaps config names automagically.
            The default for _nick is {'sourcetype_log':'sourcetype'}

    example:
    pretend we have this config

        hubblestack:
          returner:
            splunk:
              - token: feedbeef-feed-dead-beef-feeddeadbeef
                indexer: index.me.bro.hostname.org
                port: 12345
                index: hubble
                add_query_to_sourcetype: True
                sourcetype_nova: hubble_audit
                sourcetype_nebula: hubble_osquery
                sourcetype_pulsar: hubble_fim
                sourcetype_log: hubble_log
                http_event_collector_ssl_verify: false

   consider
       get_splunk_options(sourcetype='blah')
   confusingly, this gives the result
       [ { ... 'sourcetype': 'hubble_log' ... } ]
   because the default for _nick remaps the default sourcetype_log to sourcetype, which gives the above result

   more examples:

       get_splunk_options(sourcetype='blah', _nick={})
       [ { ... 'sourcetype': 'blah' ... } ]

       get_splunk_options(sourcetype_nebulous='blah', _nick={'sourcetype_nebulous': 'sourcetype'})
       [ { ... 'sourcetype': 'blah' ... } ]

       get_splunk_options(sourcetype_nebula='blah', _nick={'sourcetype_nebula': 'sourcetype'})
       [ { ... 'sourcetype': 'hubble_osquery' ... } ]

    """
    if not spaces:
        spaces = ['hubblestack:returner:splunk']

    for space in spaces:
        for modality in MODALITIES:
            ret = _get_splunk_options(space, modality, **copy.deepcopy(kw))
            if ret:
                return ret

    return []

def make_hec_args(opts):
    if isinstance(opts, (tuple,list)):
        return [ make_hec_args(i) for i in opts ]
    a  = (opts['token'], opts['index'], opts['indexer'])
    kw = {
        'http_event_port': opts['port'],
        'http_event_server_ssl': opts['http_event_server_ssl'],
        'http_event_collector_ssl_verify': opts['http_event_collector_ssl_verify'],
        'proxy': opts['proxy'],
        'timeout': opts['timeout'],
        'disk_queue': opts['disk_queue'],
        'disk_queue_size': opts['disk_queue_size'],
        'disk_queue_compression': opts['disk_queue_compression'],
    }

    return (a, kw)


def _setup_for_testing():
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

"""
File that holds common functions shared among the graylog returners
"""
from collections import namedtuple

Defaults = namedtuple('Defaults', ['port', 'sourcetype'])

MODULE_TO_DEFAULTS = {'pulsar': Defaults(port='12202', sourcetype='hubble_fim'),
                      'nova': Defaults(port='12201', sourcetype='hubble_audit'),
                      'nebula': Defaults(port='12022', sourcetype='hubble_osquery')}

def _get_options(module_name):
    """
    Function that aggregates the configs for graylog and returns them as a list of dicts.
    ``module_name``: a string that tells the module from which the function is called, should be
                     `nova`, `nebula` or `pulsar`
    """
    if __salt__['config.get']('hubblestack:returner:graylog'):
        returner_opts = __salt__['config.get']('hubblestack:returner:graylog')
        if not isinstance(returner_opts, list):
            returner_opts = [returner_opts]
        return [_process_opt(opt, module_name) for opt in returner_opts]
    try:
        if module_name == 'nova':
            sourcetype = __salt__['config.get']('hubblestack:returner:graylog:sourcetype')
            custom_fields = __salt__['config.get']('hubblestack:returner:graylog:custom_fields', [])
        else:
            sourcetype = __salt__['config.get'](
                'hubblestack:{}:returner:graylog:sourcetype'.format(module_name))
            custom_fields = __salt__['config.get'](
                'hubblestack:{}:returner:graylog:custom_fields'.format(module_name), [])

        graylog_opts = {'gelfhttp': __salt__['config.get']('hubblestack:returner:graylog:gelfhttp'),
                        'sourcetype': sourcetype,
                        'custom_fields': custom_fields,
                        'port': __salt__['config.get']('hubblestack:returner:graylog:port'),
                        'http_input_server_ssl': __salt__['config.get'](
                            'hubblestack:{}:returner:graylog:gelfhttp_ssl'.format(module_name),
                            True),
                        'proxy': __salt__['config.get'](
                            'hubblestack:pulsar:returner:graylog:proxy'.format(module_name), {}),
                        'timeout': __salt__['config.get'](
                            'hubblestack:{}:returner:graylog:timeout'.format(module_name), 9.05)}
    except:
        return None

    return [graylog_opts]


def _process_opt(opt, module_name):
    """
    Helper function that extracts certain fields from the opt dict and assembles the processed dict
    - a cleaner way of holding opt fields
    """
    module_defaults = MODULE_TO_DEFAULTS[module_name]
    processed = {'gelfhttp': opt.get('gelfhttp'),
                 'port': str(opt.get('port', module_defaults.port)),
                 'custom_fields': opt.get('custom_fields', []),
                 'sourcetype': opt.get('sourcetype_pulsar', module_defaults.sourcetype),
                 'proxy': opt.get('proxy', {}),
                 'timeout': opt.get('timeout', 9.05)}
    if module_name == 'nova':
        processed['http_input_server_ssl'] = opt.get('gelfhttp_ssl', True)
    else:
        processed['gelfhttp_ssl'] = opt.get('gelfhttp_ssl', True)
    return processed

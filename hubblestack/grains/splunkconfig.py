# -*- coding: utf-8 -*-
'''
Attempt to load alternate splunk config from the hubble.d/ directory and store
in grains for use by the splunk returners. This way splunk config changes don't
require a hubble restart.
'''
import os
import yaml


def splunkconfig():
    """
    Walk the hubble.d/ directory and read in any .conf files using YAML. If
    splunk config is found, place it in grains and return.
    """
    configdir = os.path.join(os.path.dirname(__opts__['configfile']), 'hubble.d')
    ret = {}
    if not os.path.isdir(configdir):
        ret = _splunkindex(ret)
        return ret
    try:
        for root, _dirs, files in os.walk(configdir):
            for conf_file in files:
                if not conf_file.endswith('.conf'):
                    pass
                fpath = os.path.join(root, conf_file)
                try:
                    with open(fpath, 'r') as conf_file_handler:
                        config = yaml.safe_load(conf_file_handler)
                    if config.get('hubblestack', {}).get('returner', {}).get('splunk'):
                        ret = {'hubblestack': config['hubblestack']}
                except Exception:
                    pass
    except Exception:
        pass
    ret = _splunkindex(ret)
    return ret


def _splunkindex(grains=None):
    """
    If splunk config is found, set the ``index`` to the ``splunkindex`` grain.

    Grains take priority over opts.

    If the grains and opts splunk index differ, set ``splunk_grains_fallback``
    grain (with the old index) so that we know that splunk config has changed
    (via grains) since hubble startup.
    """
    if grains is None:
        grains = {}
    index = None

    # Opts, new-style config
    try:
        index = __opts__['hubblestack']['returner']['splunk'][0]['index']
    except Exception:
        pass

    # Opts, old-style config
    try:
        index = __opts__['hubblestack']['returner']['splunk']['index']
    except Exception:
        pass

    opts_index = index

    # Grains, new-style config
    try:
        index = grains['hubblestack']['returner']['splunk'][0]['index']
    except Exception:
        pass

    # Grains, old-style config
    try:
        index = grains['hubblestack']['returner']['splunk']['index']
    except Exception:
        pass

    if index:
        grains['splunkindex'] = index
        # Check if grains differ from opts, and note if that's the case
        if opts_index != index:
            grains['splunk_grains_fallback'] = opts_index
    return grains

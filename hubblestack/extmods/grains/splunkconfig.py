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
        return ret
    try:
        for root, dirs, files in os.walk(configdir):
            for f in files:
                if f.endswith('.conf'):
                    fpath = os.path.join(root, f)
                    try:
                        with open(fpath, 'r') as fh:
                            config = yaml.safe_load(fh)
                        if config.get('hubblestack', {}).get('returner', {}).get('splunk'):
                            ret = {'hubblestack': config['hubblestack']}
                    except:
                        pass
    except:
        pass
    ret = _splunkindex(ret)
    return ret


def _splunkindex(grains=None):
    """
    If splunk config is found, set the ``index`` to the ``splunkindex`` grain.

    Search grains (passed in), then config.
    """
    if grains is None:
        grains = {}

    # Grains, old-style config
    try:
        grains['splunkindex'] = grains['hubblestack']['returner']['splunk']['index']
        return grains
    except Exception:
        pass

    # Grains, new-style config
    try:
        grains['splunkindex'] = grains['hubblestack']['returner']['splunk'][0]['index']
        return grains
    except Exception:
        pass

    # Opts, old-style config
    try:
        grains['splunkindex'] = opts['hubblestack']['returner']['splunk']['index']
        return grains
    except Exception:
        pass

    # Opts, new-style config
    try:
        grains['splunkindex'] = opts['hubblestack']['returner']['splunk'][0]['index']
        return grains
    except Exception:
        pass

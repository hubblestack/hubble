# -*- coding: utf-8 -*-
'''
Attempt to load alternate splunk config from the hubble.d/ directory and store
in grains for use by the splunk returners. This way splunk config changes don't
require a hubble restart.
'''
import os
import yaml


def splunkconfig():
    '''
    Walk the hubble.d/ directory and read in any .conf files using YAML. If
    splunk config is found, place it in grains and return.
    '''
    configdir = os.path.join(os.path.dirname(__opts__['configfile']), 'hubble.d')
    ret = {}
    if not os.path.isdir(configdir):
        return ret
    try:
        for root, dirs, files in os.walk(configdir):
            for f in files:
                if f.endswith('.conf'):
                    fpath = os.path.join(root, fpath)
                    try:
                        with open(fpath, 'r') as fh:
                            config = yaml.safe_load(fh)
                        if config.get('hubblestack', {}).get('returner', {}).get('splunk'):
                            ret = {'hubblestack': config['hubblestack']}
                    except:
                        pass
    except:
        pass
    return ret

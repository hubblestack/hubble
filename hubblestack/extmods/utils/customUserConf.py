import json
import yaml
import logging
import hubblestack.log

log = logging.getLogger(__name__)
basePath = '/etc/hubble/hubble.d/'
default_config_name = 'user.conf'

def parse_configure_option(configure_options):
    try:
        keys = configure_options.split(" ")
        configure_options_dict = {}
        for str in keys:
            key = str.split("=")[0]
            value = str.split("=")[1]
            configure_options_dict[key] = value
    except:
        print('some error occured, parameters format incorrect')
    return configure_options_dict

def createUserConf(__opts__, configure_options):
    print('inside createUserConf')
    configure_options_dict = parse_configure_option(configure_options)
    splunkConf = __opts__.get('hubblestack', [])
    if('filename' in configure_options_dict):
        user_config_filename = basePath + configure_options_dict['filename']
    else:
        user_config_filename = basePath + default_config_name
    encodedsplunkConf = json.dumps(splunkConf)
    yamlSplunkConf = yaml.safe_load(encodedsplunkConf)
    inner_most = yamlSplunkConf['returner']['splunk'][0]
    if 'splunkIndex' in configure_options_dict:
        inner_most['index'] = configure_options_dict['splunkIndex']
    if 'splunkIndexer' in configure_options_dict:
        inner_most['indexer'] = configure_options_dict['splunkIndexer']
    if 'splunkToken' in configure_options_dict:
        inner_most['token'] = configure_options_dict['splunkToken']
    if 'splunkProxy' in configure_options_dict:
        inner_most['proxy'] = configure_options_dict['splunkProxy']
    if 'splunkPort' in configure_options_dict:
        inner_most['port'] = int(configure_options_dict['splunkPort'])
    with open(user_config_filename, 'w') as outfile:
        yaml.safe_dump(yamlSplunkConf, outfile, default_flow_style=False, sort_keys=False)
    outfile.close()
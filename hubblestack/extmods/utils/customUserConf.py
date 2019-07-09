import json
import yaml
import logging
import hubblestack.log

log = logging.getLogger(__name__)
base_path = '/etc/hubble/hubble.d/'
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

def create_user_conf(__opts__, configure_options):
    print('inside create_user_conf')
    configure_options_dict = parse_configure_option(configure_options)
    splunk_conf = __opts__.get('hubblestack', [])
    if('confname' in configure_options_dict):
        user_config_filename = base_path + configure_options_dict['confname']
    else:
        user_config_filename = base_path + default_config_name
    encoded_splunk_conf = json.dumps(splunk_conf)
    yaml_splunk_conf = yaml.safe_load(encoded_splunk_conf)
    inner_most = yaml_splunk_conf['returner']['splunk'][0]
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
        yaml.safe_dump(yaml_splunk_conf, outfile, default_flow_style=False, sort_keys=False)
    outfile.close()
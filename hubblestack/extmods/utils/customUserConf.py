import json
import yaml
import logging
base_path_linux = '/etc/hubble/hubble.d'
base_path_windows = 'C:\\Program Files (x86)\\Hubble\\etc\\hubble\\hubble.d\\'
log = logging.getLogger(__name__)
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


def create_user_conf(splunk_conf, configure_options, is_windows):
    print('creating custom conf')
    configure_options_dict = parse_configure_option(configure_options)
    base_path = base_path_windows if is_windows else base_path_linux
    if('confname' in configure_options_dict):
        user_config_filename = base_path + configure_options_dict['confname']
    else:
        user_config_filename = base_path + default_config_name
    encoded_splunk_conf = json.dumps(splunk_conf)
    yaml_splunk_conf = yaml.safe_load(encoded_splunk_conf)
    inner_most = yaml_splunk_conf['returner']['splunk'][0]
    if 'splunk_index' in configure_options_dict:
        inner_most['index'] = configure_options_dict['splunk_index']
    if 'splunk_indexer' in configure_options_dict:
        inner_most['indexer'] = configure_options_dict['splunk_indexer']
    if 'splunk_token' in configure_options_dict:
        inner_most['token'] = configure_options_dict['splunk_token']
    if 'splunk_proxy' in configure_options_dict:
        inner_most['proxy'] = configure_options_dict['splunk_proxy']
    if 'splunk_port' in configure_options_dict:
        inner_most['port'] = int(configure_options_dict['splunk_port'])
    with open(user_config_filename, 'w') as outfile:
        yaml.safe_dump(yaml_splunk_conf, outfile, default_flow_style=False, sort_keys=False)
    print('custom conf created at ' + user_config_filename)
    outfile.close()

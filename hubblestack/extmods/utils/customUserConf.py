import json
import yaml
import logging
import hubblestack.log

log = logging.getLogger(__name__)
global __opts__

def createUserConf():
    print('inside create user conf')
    splunkIndex = 'mera_personal_index'
    splunk_token = 'mera_personal_token'
    splunkIndexer = 'mera_indexer'
    splunkConf = __opts__.get('hubblestack', [])
    log.info(type(splunkConf))
    log.info('Moody')
    log.info(splunkConf)
    basePath = '/etc/hubble/hubble.d/'
    outputFile = basePath + 'abc.conf'
    encodedsplunkConf = eval(json.dumps(splunkConf))
    inner_most = encodedsplunkConf['returner']['splunk'][0]
    for key, value in inner_most.items():
        if key == 'index':
            print(value)
            inner_most['index'] = splunkIndex
        elif key == 'indexer':
            print(value)
            inner_most['indexer'] = splunkIndexer
        elif key == 'token':
            print(value)
            inner_most['token'] = splunk_token
    with open(outputFile, 'w') as outfile:
        yaml.dump(encodedsplunkConf, outfile, default_flow_style=False)
    outfile.close()
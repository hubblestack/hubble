import json
import yaml
import logging
import hubblestack.log

log = logging.getLogger(__name__)

def createUserConf(__opts__):
    print('inside create user conf')
    splunkIndex = 'mera_personal_index'
    splunk_token = 'mera_personal_token'
    splunkIndexer = 'mera_indexer'
    log.info('Moody')
    log.info(__opts__)
    splunkConf = __opts__.get('hubblestack', [])
    log.info(splunkConf)
    log.info(type(splunkConf))
    basePath = '/etc/hubble/hubble.d/'
    outputFile = basePath + 'abc.conf'
    true=True
    encodedsplunkConf = eval(json.dumps(splunkConf))
    log.info(encodedsplunkConf)
    inner_most = encodedsplunkConf['returner']['splunk'][0]
    log.info(inner_most)
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
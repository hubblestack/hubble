'''
HubbleStack Cloud Details Grain
'''

import requests


def get_cloud_details():
    # Gather all cloud details and return them, along with the fieldnames

    grains = {}

    aws = _get_aws_details()
    azure = _get_azure_details()
    gcp = _get_gcp_details()

    if aws['cloud_details']:
        grains.update(aws)
    if azure['cloud_details']:
        grains.update(azure)
    if gcp['cloud_details']:
        grains.update(gcp)

    return grains


def _get_aws_details():
    # Gather amazon information if present
    ret = {}
    aws = {}
    aws['cloud_instance_id'] = None
    aws['cloud_account_id'] = None
    aws['cloud_type'] = 'aws'

    try:
        aws['cloud_account_id'] = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document',
                                               timeout=3).json().get('accountId', 'unknown')
        # AWS account id is always an integer number
        # So if it's an aws machine it must be a valid integer number
        # Else it will throw an Exception
        int(aws['cloud_account_id'])

        aws['cloud_instance_id'] = requests.get('http://169.254.169.254/latest/meta-data/instance-id',
                                                timeout=3).text
    except (requests.exceptions.RequestException, ValueError):
        # Not on an AWS box
        aws = None

    ret['cloud_details'] = aws
    return ret


def _get_azure_details():
    # Gather azure information if present
    ret = {}
    azure = {}
    azure['cloud_instance_id'] = None
    azure['cloud_account_id'] = None
    azure['cloud_type'] = 'azure'
    azureHeader = {'Metadata': 'true'}
    try:
        id = requests.get('http://169.254.169.254/metadata/instance/compute?api-version=2017-08-01',
                          headers=azureHeader, timeout=3).json()
        azure['cloud_instance_id'] = id['vmId']
        azure['cloud_account_id'] = id['subscriptionId']

    except (requests.exceptions.RequestException, ValueError):
        # Not on an Azure box
        azure = None

    ret['cloud_details'] = azure
    return ret

def _get_gcp_details():
    # Gather google compute platform information if present
    ret = {}
    gcp = {}
    gcp_extra = {}
    gcp['cloud_instance_id'] = None
    gcp['cloud_account_id'] = None
    gcp['cloud_type'] = 'gcp'
    gcp_header = {'Metadata-Flavor': 'Google'}
    try:
        gcp['cloud_instance_id'] = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/id',
                                                headers=gcp_header, timeout=3).text
        gcp['cloud_account_id'] = requests.get('http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id',
                                               headers=gcp_header, timeout=3).text
    except (requests.exceptions.RequestException, ValueError):
        # Not on gcp box
        gcp = None
    try:
        gcp_extra['cloud_project_id'] = requests.get('http://metadata.google.internal/computeMetadata/v1/project/project-id',
                                                     headers=gcp_header, timeout=3).text
        gcp_extra['cloud_instance_name'] = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/name',
                                                        headers=gcp_header, timeout=3).text
        gcp_extra['cloud_instance_hostname'] = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/hostname',
                                                             headers=gcp_header, timeout=3).text
        gcp_extra['cloud_instance_zone'] = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/zone',
                                                        headers=gcp_header, timeout=3).text
        gcp_extra['cloud_instance_image'] = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/image',
                                                         headers=gcp_header, timeout=3).text
        gcp_extra['cloud_instance_machine_type'] = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/machine-type',
                                                                headers=gcp_header, timeout=3).text
        gcp_extra['cloud_instance_network_interfaces'] = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/?recursive=true',
                                                                      headers=gcp_header, timeout=3).json()
        gcp_extra['cloud_instance_tags'] = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/tags?recursive=true',
                                                        headers=gcp_header, timeout=3).json()
        gcp_extra['cloud_instance_attributes'] = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true',
                                                              headers=gcp_header, timeout=3).json()
    except (requests.exceptions.RequestException, ValueError):
        # Not on gcp box
        gcp_extra = None

    ret['cloud_details'] = gcp
    ret['cloud_details_extra'] = gcp_extra
    return ret

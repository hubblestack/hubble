"""
HubbleStack Cloud Details Grain
"""

import requests
import logging

log = logging.getLogger(__name__)

def get_cloud_details():
    """
    Gather all cloud details and return them, along with the fieldnames
    """
    grains = {}

    aws = _get_aws_details()
    if not aws['cloud_details']: # Unable to fetch details from AWS. Let's try from Azure
        log.debug("Unable to fetch AWS details. Now trying to fetch Azure details")
        azure = _get_azure_details()
        if not azure['cloud_details']: # Unable to fetch details from Azure. Let's try from GCP
            log.debug("Unable to fetch Azure details. Now trying to fetch GCP details")
            gcp = _get_gcp_details()
            if gcp['cloud_details']:
                log.debug("Fetched instance metadata from GCP")
                grains.update(gcp)
            else:
                log.error("Unable to fetch details from AWS/Azure/GCP. Please verify the instance settings.")
        else:
            log.debug("Fetched instance metadata from Azure")
            grains.update(azure)
    else:
        log.debug("Fetched instance metadata from AWS")
        grains.update(aws)

    return grains


def _get_aws_details():
    """
    Gather amazon information if present
    """
    ret = {}
    aws_extra = {}
    aws = {'cloud_instance_id': None, 'cloud_account_id': None, 'cloud_type': 'aws'}
    proxies = {'http': None}

    try:
        ttl_header = {'X-aws-ec2-metadata-token-ttl-seconds': '300'}
        token_url = 'http://169.254.169.254/latest/api/token'
        token_request = requests.put(token_url, headers=ttl_header, timeout=3, proxies=proxies)
        token = token_request.text
        aws_token_header = {'X-aws-ec2-metadata-token': token}
        response = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document',
                            headers=aws_token_header, timeout=3, proxies=proxies)
        if response.status_code == requests.codes.ok:
            res = response.json()
            aws['cloud_account_id'] = res.get('accountId', 'unknown')

            # AWS account id is always an integer number
            # So if it's an aws machine it must be a valid integer number
            # Else it will throw an Exception
            int(aws['cloud_account_id'])
        else:
            raise ValueError("Error while fetching AWS account id. Got status code: %s " % (response.status_code))

        response = requests.get('http://169.254.169.254/latest/meta-data/instance-id',
                                headers=aws_token_header, timeout=3, proxies=proxies)
        if response.status_code == requests.codes.ok:
            aws['cloud_instance_id'] = response.text
        else:
            raise ValueError("Error while fetching AWS account id. Got status code: %s " % (response.status_code))
    except (requests.exceptions.RequestException, ValueError) as e:
        log.error(e)
        # Not on an AWS box
        aws = None
    if aws:
        try:
            aws_extra['cloud_private_ip'] = res.get('privateIp')
            aws_extra['cloud_instance_type'] = res.get('instanceType')
            aws_extra['cloud_availability_zone'] = res.get('availabilityZone')
            aws_extra['cloud_ami_id'] = res.get('imageId')
            aws_extra['cloud_region'] = res.get('region')
            r = requests.get('http://169.254.169.254/latest/meta-data/public-hostname',
                             headers=aws_token_header, timeout=3, proxies=proxies)
            if r.status_code == requests.codes.ok:
                aws_extra['cloud_public_hostname'] = r.text
            r = requests.get('http://169.254.169.254/latest/meta-data/public-ipv4',
                             headers=aws_token_header, timeout=3, proxies=proxies)
            if r.status_code == requests.codes.ok:
                aws_extra['cloud_public_ipv4'] = r.text
            r = requests.get('http://169.254.169.254/latest/meta-data/local-hostname',
                             headers=aws_token_header, timeout=3, proxies=proxies)
            if r.status_code == requests.codes.ok:
                aws_extra['cloud_private_hostname'] = r.text
            for key in list(aws_extra):
                if not aws_extra[key]:
                    aws_extra.pop(key)

        except (requests.exceptions.RequestException, ValueError) as e:
            log.error(e)
            aws_extra = None

    ret['cloud_details'] = aws
    ret['cloud_details_extra'] = aws_extra
    return ret


def _get_azure_details():
    """
    Gather azure information if present
    """
    ret = {}
    azure_extra = {}
    azure = {'cloud_instance_id': None, 'cloud_account_id': None, 'cloud_type': 'azure'}
    azure_header = {'Metadata': 'true'}
    proxies = {'http': None}

    try:
        # Reminder: rev the api version for access to more details
        response = requests.get(
            'http://169.254.169.254/metadata/instance/compute?api-version=2017-08-01',
            headers=azure_header, timeout=3, proxies=proxies)
        if response.status_code == requests.codes.ok:
            instance_info = response.json()
            azure['cloud_instance_id'] = instance_info['vmId']
            azure['cloud_account_id'] = instance_info['subscriptionId']
        else:
            raise ValueError("Error while fetching Azure instance metadata. Got status code: %s " % (response.status_code))
    except (requests.exceptions.RequestException, ValueError) as e:
        log.error(e)
        # Not on an Azure box
        azure = None

    if azure:
        try:
            azure_extra['cloud_resource_group_name'] = instance_info['resourceGroupName']
            azure_extra['cloud_location'] = instance_info['location']
            azure_extra['cloud_name'] = instance_info['name']
            azure_extra['cloud_image_offer'] = instance_info['offer']
            azure_extra['cloud_os_type'] = instance_info['osType']
            azure_extra['cloud_image_publisher'] = instance_info['publisher']
            azure_extra['cloud_tags'] = instance_info['tags']
            azure_extra['cloud_image_version'] = instance_info['version']
            azure_extra['cloud_size'] = instance_info['vmSize']
            response = requests.get(
                'http://169.254.169.254/metadata/instance/network/interface?api-version=2017-08-01',
                headers=azure_header, timeout=3, proxies=proxies)
            if response.status_code == requests.codes.ok:
                interface_list = response.json()
                for counter, value in enumerate(interface_list):
                    grain_name_private_ipv4 = "cloud_interface_{0}_private_ipv4".format(counter)
                    azure_extra[grain_name_private_ipv4] = value['ipv4']['ipAddress'][0][
                        'privateIpAddress']

                    grain_name_public_ipv4 = "cloud_interface_{0}_public_ipv4".format(counter)
                    azure_extra[grain_name_public_ipv4] = value['ipv4']['ipAddress'][0][
                        'publicIpAddress']

                    grain_name_mac = "cloud_interface_{0}_mac_address".format(counter)
                    azure_extra[grain_name_mac] = value['macAddress']

                for key in list(azure_extra):
                    if not azure_extra[key]:
                        azure_extra.pop(key)
            else:
                raise ValueError("Error while fetching metadata for Azure instance: %s. Got status code: %s" % (azure['cloud_instance_id'], response.status_code))
        except (requests.exceptions.RequestException, ValueError) as e:
            log.error(e)
            azure_extra = None

    ret['cloud_details'] = azure
    ret['cloud_details_extra'] = azure_extra
    return ret


def _get_gcp_details():
    # Gather google compute platform information if present
    ret = {}
    gcp_extra = {}
    gcp = {'cloud_instance_id': None, 'cloud_account_id': None, 'cloud_type': 'gcp'}
    gcp_header = {'Metadata-Flavor': 'Google'}
    proxies = {'http': None}
    metadata = {}

    try:
        response = requests.get(
            'http://metadata.google.internal/computeMetadata/v1/?recursive=true',
            headers=gcp_header, timeout=3, proxies=proxies)
        if response.status_code == requests.codes.ok:
            metadata = response.json()
            gcp['cloud_instance_id'] = metadata['instance']['id']
            gcp['cloud_account_id'] = metadata['project']['numericProjectId']
        else:
            raise ValueError("Error while fetching GCP instance metadata. Got status code: %s" % (response.status_code))

    except (requests.exceptions.RequestException, KeyError, ValueError) as e:
        log.error(e)
        # Not on gcp box
        gcp = None
    if gcp:
        try:
            # build gcp extra
            gcp_extra = _build_gcp_extra(metadata)
            for key in gcp_extra.copy():
                if not gcp_extra[key]:
                    gcp_extra.pop(key)
        except (requests.exceptions.RequestException, KeyError, ValueError) as e:
            log.error(e)
            gcp_extra = None

    ret['cloud_details'] = gcp
    ret['cloud_details_extra'] = gcp_extra
    return ret


def _build_gcp_extra(metadata):
    """ Helper function to build the gcp extra dict """
    gcp_extra= {}
    gcp_extra['cloud_project_id']=metadata['project']['projectId']
    gcp_extra['cloud_name'] = metadata['instance']['name']
    gcp_extra['cloud_hostname'] = metadata['instance']['hostname']
    gcp_extra['cloud_zone'] = metadata['instance']['zone']
    gcp_extra['cloud_image'] = metadata['instance']['image']
    gcp_extra['cloud_machine_type'] = metadata['instance']['machineType']
    gcp_extra['cloud_tags'] = metadata['instance']['tags']
    interface_list = metadata['instance']['networkInterfaces']

    for counter, value in enumerate(interface_list):
        grain_name_network = "cloud_interface_{0}_network".format(counter)
        gcp_extra[grain_name_network] = value['network']

        grain_name_ip = "cloud_interface_{0}_ip".format(counter)
        gcp_extra[grain_name_ip] = value['ip']

        grain_name_subnetmask = "cloud_interface_{0}_subnetmask".format(counter)
        gcp_extra[grain_name_subnetmask] = value['subnetmask']

        grain_name_mac = "cloud_interface_{0}_mac_address".format(counter)
        gcp_extra[grain_name_mac] = value['mac']

        grain_name_forwardedips = "cloud_interface_{0}_forwarded_ips".format(counter)
        gcp_extra[grain_name_forwardedips] = ','.join(value['forwardedIps'])

        grain_name_targetips = "cloud_interface_{0}_target_ips".format(counter)
        gcp_extra[grain_name_targetips] = ','.join(value['targetInstanceIps'])

        grain_name_accessconfig_external_ips = "cloud_interface_{0}_" \
                                               "accessconfigs_external_ips".format(counter)
        external_ips_list = [item['externalIp'] for item in value['accessConfigs'] if
                             'externalIp' in item]
        gcp_extra[grain_name_accessconfig_external_ips] = ','.join(external_ips_list)

    return gcp_extra

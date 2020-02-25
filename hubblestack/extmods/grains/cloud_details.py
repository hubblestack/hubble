"""
HubbleStack Cloud Details Grain
"""

import requests


def get_cloud_details():
    """
    Gather all cloud details and return them, along with the fieldnames
    """
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
        res = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document',
                            headers=aws_token_header, timeout=3, proxies=proxies).json()
        aws['cloud_account_id'] = res.get('accountId', 'unknown')

        # AWS account id is always an integer number
        # So if it's an aws machine it must be a valid integer number
        # Else it will throw an Exception
        int(aws['cloud_account_id'])
        aws['cloud_instance_id'] = requests.get('http://169.254.169.254/latest/meta-data/instance-id',
                                                headers=aws_token_header, timeout=3,
                                                proxies=proxies).text
    except (requests.exceptions.RequestException, ValueError):
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

        except (requests.exceptions.RequestException, ValueError):
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
        instance_info = requests.get(
            'http://169.254.169.254/metadata/instance/compute?api-version=2017-08-01',
            headers=azure_header, timeout=3, proxies=proxies).json()
        azure['cloud_instance_id'] = instance_info['vmId']
        azure['cloud_account_id'] = instance_info['subscriptionId']

    except (requests.exceptions.RequestException, ValueError):
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
            interface_list = requests.get(
                'http://169.254.169.254/metadata/instance/network/interface?api-version=2017-08-01',
                headers=azure_header, timeout=3, proxies=proxies).json()
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

        except (requests.exceptions.RequestException, ValueError):
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

    try:
        gcp['cloud_instance_id'] = requests.get(
            'http://metadata.google.internal/computeMetadata/v1/instance/id',
            headers=gcp_header, timeout=3, proxies=proxies).text
        gcp['cloud_account_id'] = requests.get(
            'http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id',
            headers=gcp_header, timeout=3, proxies=proxies).text
    except (requests.exceptions.RequestException, ValueError):
        # Not on gcp box
        gcp = None
    if gcp:
        try:
            # build gcp extra
            gcp_extra = _build_gpc_extra(gcp_header, proxies)
            for key in gcp_extra:
                if not gcp_extra[key]:
                    gcp_extra.pop(key)
        except (requests.exceptions.RequestException, ValueError):
            gcp_extra = None

    ret['cloud_details'] = gcp
    ret['cloud_details_extra'] = gcp_extra
    return ret


def _build_gpc_extra(gcp_header, proxies):
    """ Helper function to build the gcp extra dict """
    gcp_extra = {
        'cloud_project_id': requests.get(
            'http://metadata.google.internal/computeMetadata/v1/project/project-id',
            headers=gcp_header, timeout=3, proxies=proxies).text,
        'cloud_name': requests.get(
            'http://metadata.google.internal/computeMetadata/v1/instance/name',
            headers=gcp_header, timeout=3, proxies=proxies).text,
        'cloud_hostname': requests.get(
            'http://metadata.google.internal/computeMetadata/v1/instance/hostname',
            headers=gcp_header, timeout=3, proxies=proxies).text,
        'cloud_zone': requests.get(
            'http://metadata.google.internal/computeMetadata/v1/instance/zone',
            headers=gcp_header, timeout=3, proxies=proxies).text,
        'cloud_image': requests.get(
            'http://metadata.google.internal/computeMetadata/v1/instance/image',
            headers=gcp_header, timeout=3, proxies=proxies).text,
        'cloud_machine_type': requests.get(
            'http://metadata.google.internal/computeMetadata/v1/instance/machine-type',
            headers=gcp_header, timeout=3, proxies=proxies).text,
        'cloud_tags': requests.get(
            'http://metadata.google.internal/computeMetadata/v1/instance/tags?recursive=true',
            headers=gcp_header, timeout=3, proxies=proxies).json()}
    interface_list = requests.get(
        'http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces'
        '/?recursive=true', headers=gcp_header, timeout=3, proxies=proxies).json()

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

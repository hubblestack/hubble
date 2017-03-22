'''
HubbleStack AWS Details

:maintainer: HubbleStack
:platform: All
:requires: SaltStack
'''

import requests

def get_aws_details():
    # Gather amazon information if present
    aws = {}
    aws['aws_ami_id'] = None
    aws['aws_instance_id'] = None
    aws['aws_account_id'] = None

    try:
        aws['aws_account_id'] = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document',
                                      timeout=1).json().get('accountId', 'unknown')
        # AWS account id is always an integer number
        # So if it's an aws machine it must be a valid integer number
        # Else it will throw an Exception
        aws['aws_account_id'] = int(aws['aws_account_id'])

        aws['aws_ami_id'] = requests.get('http://169.254.169.254/latest/meta-data/ami-id',
                                  timeout=1).text
        aws['aws_instance_id'] = requests.get('http://169.254.169.254/latest/meta-data/instance-id',
                                       timeout=1).text
    except (requests.exceptions.RequestException, ValueError):
        # Not on an AWS box
        aws['aws_account_id'] = None
        pass
    return aws

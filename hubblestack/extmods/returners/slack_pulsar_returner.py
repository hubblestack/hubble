# -*- coding: utf-8 -*-
"""
Return salt data via slack

This version of the returner is designed to be used with hubblestack pulsar, as
it expects the limited data which pulsar provides.

The following fields can be set in the minion conf file::

.. code-block:: yaml

    slack_pulsar.channel (required)
    slack_pulsar.api_key (required)
    slack_pulsar.username (required)
    slack_pulsar.as_user (required to see the profile picture of your bot)
    slack_pulsar.profile (optional)

Alternative configuration values can be used by prefacing the configuration.
Any values not found in the alternative configuration will be pulled from
the default location:

.. code-block:: yaml

    slack_pulsar.channel
    slack_pulsar.api_key
    slack_pulsar.username
    slack_pulsar.as_user

Slack settings may also be configured as:

.. code-block:: yaml

    slack:
        channel: RoomName
        api_key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        username: user
        as_user: true

    alternative.slack:
        room_id: RoomName
        api_key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        from_name: user@email.com

    slack_profile:
        api_key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        from_name: user@email.com

    slack:
        profile: slack_profile
        channel: RoomName

    alternative.slack:
        profile: slack_profile
        channel: RoomName

"""


# Import Python libs
import pprint
import logging
import urllib.request, urllib.parse, urllib.error

# pylint: disable=import-error,no-name-in-module,redefined-builtin
from salt.ext.six.moves.urllib.parse import urljoin as _urljoin
# pylint: disable=import-error,no-name-in-module
import salt.ext.six.moves.http_client
# pylint: enable=import-error,no-name-in-module,redefined-builtin

# Import Salt Libs
import salt.returners

log = logging.getLogger(__name__)

__virtualname__ = 'slack_pulsar'


API_URL = 'https://slack.com'

SLACK_FUNCTIONS = {
    'rooms': {
        'request': 'channels.list',
        'response': 'channels',
        },
    'users': {
        'request': 'users.list',
        'response': 'members',
        },
    'message': {
        'request': 'chat.postMessage',
        'response': 'channel',
        },
}


def _get_options(ret=None):
    """
    Get the slack options from salt.
    """

    defaults = {'channel': '#general'}

    attrs = {'slack_profile': 'profile',
             'channel': 'channel',
             'username': 'username',
             'as_user': 'as_user',
             'api_key': 'api_key',
            }

    profile_attr = 'slack_profile'

    profile_attrs = {'from_jid': 'from_jid',
                     'api_key': 'api_key',
                     'api_version': 'api_key'
                    }

    _options = salt.returners.get_returner_options(__virtualname__,
                                                   ret,
                                                   attrs,
                                                   profile_attr=profile_attr,
                                                   profile_attrs=profile_attrs,
                                                   __salt__=__salt__,
                                                   __opts__=__opts__,
                                                   defaults=defaults)
    return _options


def __virtual__():
    """
    Return virtual name of the module.

    :return: The virtual name of the module.
    """
    return __virtualname__


def _query(function,
           api_key=None,
           args=None,
           method='GET',
           header_dict=None,
           data=None):
    """
    Slack object method function to construct and execute on the API URL.

    :param api_key:     The Slack api key.
    :param function:    The Slack api function to perform.
    :param method:      The HTTP method, e.g. GET or POST.
    :param data:        The data to be sent for POST method.
    :return:            The json response from the API call or False.
    """
    query_params = {}

    ret = {'message': '',
           'res': True}

    if not api_key:
        try:
            options = __salt__['config.option']('slack')
            if not api_key:
                api_key = options.get('api_key')
        except (NameError, KeyError, AttributeError):
            log.error('No Slack api key found.')
            ret['message'] = 'No Slack api key found.'
            ret['res'] = False
            return ret

    base_url = _urljoin(API_URL, '/api/')
    path = SLACK_FUNCTIONS.get(function).get('request')
    url = _urljoin(base_url, path, False)

    if not isinstance(args, dict):
        query_params = {}
    query_params['token'] = api_key

    if header_dict is None:
        header_dict = {}

    if method != 'POST':
        header_dict['Accept'] = 'application/json'

    result = salt.utils.http.query(
        url,
        method,
        params=query_params,
        data=data,
        decode=True,
        status=True,
        header_dict=header_dict,
        opts=__opts__,
    )

    if result.get('status', None) == salt.ext.six.moves.http_client.OK:
        _result = result['dict']
        response = SLACK_FUNCTIONS.get(function).get('response')
        if 'error' in _result:
            ret['message'] = _result['error']
            ret['res'] = False
            return ret
        ret['message'] = _result.get(response)
        return ret
    elif result.get('status', None) == salt.ext.six.moves.http_client.NO_CONTENT:
        return True
    log.debug(url)
    log.debug(query_params)
    log.debug(data)
    log.debug(result)
    _result = result['dict']
    if 'error' in _result:
        ret['message'] = _result['error']
        ret['res'] = False
        return ret
    ret['message'] = _result.get('response')
    return ret


def _post_message(channel,
                  message,
                  username,
                  as_user,
                  api_key=None):
    """
    Send a message to a Slack room.
    :param channel:     The room name.
    :param message:     The message to send to the Slack room.
    :param username:    Specify who the message is from.
    :param as_user:     Sets the profile picture which have been added through Slack itself.
    :param api_key:     The Slack api key, if not specified in the configuration.
    :param api_version: The Slack api version, if not specified in the configuration.
    :return:            Boolean if message was sent successfully.
    """

    parameters = dict()
    parameters['channel'] = channel
    parameters['username'] = username
    parameters['as_user'] = as_user
    parameters['text'] = '```' + message + '```'  # pre-formatted, fixed-width text

    # Slack wants the body on POST to be urlencoded.
    result = _query(function='message',
                    api_key=api_key,
                    method='POST',
                    header_dict={'Content-Type': 'application/x-www-form-urlencoded'},
                    data=urllib.parse.urlencode(parameters))

    log.debug('result %s', result)

    return bool(result)


def returner(ret):
    """
    Send an slack message with the data
    """

    _options = _get_options(ret)

    channel = _options.get('channel')
    username = _options.get('username')
    as_user = _options.get('as_user')
    api_key = _options.get('api_key')

    if not channel:
        log.error('slack_pulsar.channel not defined in salt config')
        return None

    if not username:
        log.error('slack_pulsar.username not defined in salt config')
        return None

    if not as_user:
        log.error('slack_pulsar.as_user not defined in salt config')
        return None

    if not api_key:
        log.error('slack_pulsar.api_key not defined in salt config')
        return None

    if ret and isinstance(ret, dict):
        message = ('id: {0}\r\n'
                   'return: {1}\r\n').format(__opts__['id'],
                                             pprint.pformat(ret.get('return')))
    elif ret and isinstance(ret, list):
        message = 'id: {0}\r\n'
        for return_data in ret:
            message += pprint.pformat(return_data.get('return'))
            message += '\r\n'
    else:
        log.error('Data sent to slack_pulsar formatted incorrectly')
        return None

    slack = _post_message(channel,
                          message,
                          username,
                          as_user,
                          api_key)
    return slack

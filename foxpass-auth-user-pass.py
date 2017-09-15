# Copyright (c) 2017-present, Foxpass, Inc.
# All rights reserved.
#
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# to test:
#
# create a file with two lines, first being username, second being password
# python foxpass-auth-user-pass.py /path/to/file
#

import argparse
import json
import logging
import os
import requests
import sys
import traceback

import duo_client
import ConfigParser

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)-8s %(message)s')
logger = logging.getLogger(__name__)

MAX_PACKET_SIZE = 8192
DEFAULT_API_HOST = 'https://api.foxpass.com'

CONFIG = ConfigParser.SafeConfigParser()
CONF_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'foxpass.conf')

def get_config_item(name, default=None):
    section = 'default'

    if not CONFIG.has_option(section, name):
        return default

    return CONFIG.get(section, name)


def auth_with_foxpass(username, password):
    data = {'username': username, 'password': password}
    headers = {'Authorization': 'Token %s' % get_config_item('api_key') }
    url = get_config_item('api_host', DEFAULT_API_HOST) + '/v1/authn/'
    logger.info('API request to {}'.format(url))
    reply = requests.post(url, data=json.dumps(data), headers=headers)
    data = reply.json()

    # format examples:
    # {u'status': u'ok'}
    # {u'status': u'error', u'message': u'Incorrect password'}

    if not data:
        raise Exception("Unknown error")

    if not 'status' in data:
        raise Exception("Unknown error")

    if data['status'] == 'error':
        if data['message'] == 'Incorrect password':
            logger.info("Invalid password")
            return False

        raise Exception(data['message'])

    if data['status'] == 'ok':
        return True

    return False


def two_factor(username):
    # if Duo is not configured, return success
    if not get_config_item('duo_api_host') or \
       not get_config_item('duo_ikey') or \
       not get_config_item('duo_skey'):
        logger.info("Duo not configured")
        return True

    auth_api = duo_client.Auth(
        ikey=get_config_item('duo_ikey'),
        skey=get_config_item('duo_skey'),
        host=get_config_item('duo_api_host')
    )

    response = auth_api.auth('push',
                             username=username,
                             device='auto',
                             async=False)

    # success returns:
    # {u'status': u'allow', u'status_msg': u'Success. Logging you in...', u'result': u'allow'}

    # deny returns:
    # {u'status': u'deny', u'status_msg': u'Login request denied.', u'result': u'deny'}
    if response and response['result'] == 'allow':
        return True

    logger.info("Duo failed")
    return False


def group_match(username):
    require_groups = get_config_item('require_groups')

    # if no groups were specified in the config, then allow access
    if not require_groups:
        return True

    allowed_set = set([name.strip() for name in require_groups.split(',')])

    headers = {'Authorization': 'Token %s' % get_config_item('api_key') }
    reply = requests.get(get_config_item('api_server', DEFAULT_API_HOST) + '/v1/users/' + username + '/groups/', headers=headers)
    data = reply.json()

    groups = data['data']

    user_set = set()

    for group in groups:
        user_set.add(group['name'])

    # see if user is any of the allowed groups
    if user_set.intersection(allowed_set):
        return True

    logger.info("User %s is not in one of allowed groups (%s)." % (username, list(allowed_set)))
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file')
    args = parser.parse_args()

    CONFIG.readfp(open(CONF_FILE))

    with open(args.input_file) as f:
        content = f.readlines()

    # remove whitespace characters at the end of each line
    content = [x.strip() for x in content]

    (username, password) = content

    if not get_config_item('api_key'):
        logger.error("ERROR: api_key must be set in config file.")
        return

    if auth_with_foxpass(username, password) \
       and two_factor(username) \
       and group_match(username):
        # success!
        logger.info("Authentiation success!")
        sys.exit(0)

    logger.info("Authentication failed")
    sys.exit(1)


if __name__ == '__main__':
    main()

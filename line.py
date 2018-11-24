import json
import logging
import os
import urllib
# noinspection PyCompatibility
import urllib.request
# noinspection PyCompatibility
import urllib.parse

from rauth import OAuth2Service
from flask import session

import storage

line_notify_oauth2_client = OAuth2Service(
    client_id=os.getenv('LINE_NOTIFY_CLIENT_ID'),
    client_secret=os.getenv('LINE_NOTIFY_CLIENT_SECRET'),
    name='line-notify',
    authorize_url='https://notify-bot.line.me/oauth/authorize',
    access_token_url='https://notify-bot.line.me/oauth/token',
    base_url='https://notify-bot.line.me/')


def access_token_decoder(payload):
    return json.loads(payload.decode('utf-8'))


def notify_connected(device):
    if device['line_notify_access_token'] is None:
        return
    name = 'CarProbe'
    if device['name'] is not None:
        name = device['name']

    params = {
        'message': '{} がインターネットに接続されました'.format(name)
    }
    headers = {
        'Authorization': 'Bearer {}'.format(device['line_notify_access_token']),
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    form_data = urllib.parse.urlencode(params)
    req = urllib.request.Request('https://notify-api.line.me/api/notify',
                                 form_data.encode('utf-8'), headers)
    req.method = 'POST'
    try:
        with urllib.request.urlopen(req) as res:
            result = res.read()
            logging.debug('api result: {}'.format(result))
        return True
    except OSError:
        logging.warning('LINE notify failre by api (URLError)')
        return False
    except TypeError:
        logging.warning('LINE notify failre by api (TypeError)')
        return False


def redirect_auth(form):
    auth_info = form['authorization']
    device = storage.device_by_jwt(auth_info)
    if device is None:
        return None

    redirect_uri = os.getenv('LINE_NOTIFY_REDIRECT_URI')
    state = storage.random_str(16)
    session['line_oauth_state'] = state
    session['line_oauth_callback_uri'] = form['callback_uri']
    session['line_oauth_device_key'] = device['device_key']
    url = line_notify_oauth2_client.get_authorize_url(
        response_type='code',
        redirect_uri=redirect_uri,
        scope='notify',
        state=state,
        response_mode='form_post')
    return url


def redirect_callback(form):
    code = form['code']
    state = form['state']
    session_state = session.get('line_oauth_state')
    device = storage.get_device(session.get('line_oauth_device_key'))
    redirect_uri = os.getenv('LINE_NOTIFY_REDIRECT_URI')

    if state == session_state and device is not None:
        auth_session = line_notify_oauth2_client.get_auth_session(data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri
        }, decoder=access_token_decoder)
        device['line_notify_access_token'] = auth_session.access_token
        storage.device_put(device)

    return session.get('line_oauth_callback_uri')


def get_connection_state(authorization, device_key):
    auth_type, auth_info = authorization.split(None, 1)
    if auth_type.lower() != 'bearer':
        return {'authorized': False, 'connected': False}
    device = storage.device_by_jwt(auth_info)
    if device is None:
        return {'authorized': False, 'connected': False}
    if device['device_key'] != device_key:
        return {'authorized': False, 'connected': False}

    access_token = device['line_notify_access_token']

    if access_token is None:
        return {'authorized': True, 'connected': False}

    headers = {
        'Authorization': 'Bearer {}'.format(device['line_notify_access_token']),
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    req = urllib.request.Request('https://notify-api.line.me/api/status', headers=headers)

    try:
        with urllib.request.urlopen(req) as res:
            if res.status == 401:
                device['line_notify_access_token'] = None
                storage.device_put(device)
                return {'authorized': True, 'connected': False}
            else:
                return {'authorized': True, 'connected': True}
    except OSError:
        logging.warning('LINE notify failre by api (URLError)')
        return {'authorized': True, 'connected': False}
    except TypeError:
        logging.warning('LINE notify failre by api (TypeError)')
        return {'authorized': True, 'connected': False}

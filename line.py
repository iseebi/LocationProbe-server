import logging
import os
import urllib
import urllib.request
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
    req = urllib.request.Request('https://notify-api.line.me/api/notify', urllib.parse.urlencode(params), headers)
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


def redirect_auth(authorization, form):
    auth_type, auth_info = authorization.split(None, 1)
    if auth_type != 'bearer':
        return None
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
    session_state = session['line_oauth_state']
    device = storage.get_device(session['line_oauth_device_key'])

    if state == session_state and device is not None:
        auth_session = line_notify_oauth2_client.get_auth_session(data={'code': code})
        device['line_notify_access_token'] = auth_session.access_token
        storage.device_put(device)

    return session['line_oauth_callback_uri']

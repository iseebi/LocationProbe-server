import logging
import os
import urllib
# noinspection PyCompatibility
import urllib.request

from flask import session

import storage

locapos_endpoint = 'https://locapos.com'


def redirect_auth(form):
    auth_info = form['authorization']
    device = storage.device_by_jwt(auth_info)
    if device is None:
        return None

    redirect_uri = os.getenv('LOCAPOS_REDIRECT_URI')
    state = storage.random_str(16)
    session['locapos_oauth_state'] = state
    session['locapos_oauth_callback_uri'] = form['callback_uri']
    session['locapos_oauth_device_key'] = device['device_key']
    url = '{}/oauth/authorize?response_type=token&client_id={}&redirect_uri={}'.format(
        locapos_endpoint,
        os.getenv('LOCAPOS_API_KEY'),
        redirect_uri
    )
    return url


def redirect_callback():
    device_key = session.get('locapos_oauth_device_key')
    device = storage.get_device(device_key)

    if device is None:
        return None

    return session['locapos_oauth_state']


def redirect_register(form):
    access_token = form.get('access_token')
    state = form.get('state')
    session_state = session.get('locapos_oauth_state')
    device_key = session.pop('locapos_oauth_device_key')
    device = storage.get_device(device_key)

    if state == session_state and device is not None:
        device['locapos_access_token'] = access_token
        storage.device_put(device)

    return session.get('locapos_oauth_callback_uri')


def get_connection_state(authorization):
    auth_type, auth_info = authorization.split(None, 1)
    if auth_type.lower() != 'bearer':
        return {'authorized': False, 'connected': False}
    device = storage.device_by_jwt(auth_info)
    if device is None:
        return {'authorized': False, 'connected': False}

    access_token = device['locapos_access_token']

    if access_token is None:
        return {'authorized': True, 'connected': False}

    headers = {
        'Authorization': 'Bearer {}'.format(access_token),
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    req = urllib.request.Request('https://locapos.com/api/users/me', headers=headers)

    try:
        with urllib.request.urlopen(req) as res:
            if res.status == 401:
                device['locapos_notify_access_token'] = None
                storage.device_put(device)
                return {'authorized': True, 'connected': False}
            else:
                return {'authorized': True, 'connected': True}
    except OSError:
        logging.warning('locapos failre by api (URLError)')
        return {'authorized': True, 'connected': False}
    except TypeError:
        logging.warning('locapos failre by api (TypeError)')
        return {'authorized': True, 'connected': False}

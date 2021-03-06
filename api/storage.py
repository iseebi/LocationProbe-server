import base64
import json
import random
import string

import jwt
from Crypto.PublicKey import RSA
from google.cloud import datastore

datastore_client = datastore.Client()


def random_str(n):
    # noinspection PyUnusedLocal
    return ''.join([random.choice(string.ascii_lowercase + string.digits) for i in range(n)])


def get_device(device_key):
    if device_key is None:
        return None
    key = datastore_client.key('Device', device_key)
    device = datastore_client.get(key=key)
    return device


def create_device(iot_device, name, device_key, public_key):
    device = datastore.Entity(key=datastore_client.key('Device', device_key))
    device['name'] = name
    device['public_key'] = public_key
    device['iot_topic'] = iot_device.name
    device['iot_id'] = iot_device.num_id
    device['device_key'] = device_key
    device['line_notify_access_token'] = None
    device['locapos_access_token'] = None
    datastore_client.put(device)


def generate_new_device_key():
    while True:
        key_str = random_str(40)
        datastore_client.query()
        device = get_device(key_str)
        if device is None:
            break
    return key_str


def device_by_jwt(jwt_string):
    tmp = jwt_string.split('.')
    tmp_header = tmp[0] + '=' * (-len(tmp[0]) % 4)
    header = json.loads(base64.b64decode(tmp_header).decode('utf-8'))
    device = get_device(header['kid'])
    if device is None or header['alg'] != 'RS256':
        return None

    try:
        rsa_key = RSA.importKey(device['public_key'])
        jwt.decode(jwt_string, rsa_key.exportKey(), verify=True)
    except jwt.exceptions.ExpiredSignatureError:
        return None
    except ValueError:
        return None

    return device


def device_put(device):
    datastore_client.put(device)

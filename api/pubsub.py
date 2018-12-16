import base64
import json

import line
import storage
from google.cloud import iot_v1

iot_client = iot_v1.DeviceManagerClient()
project_id = 'iseteki-carrouter'
topic = 'projects/iseteki-carrouter/locations/asia-east1/registries/probes'


def create_device(payload):
    public_key = payload['public_key']
    name = payload['name'] if ('name' in payload) else None
    new_device_key = storage.generate_new_device_key()
    iot_device = iot_client.create_device(topic, create_iot_device(new_device_key, public_key))
    storage.create_device(iot_device, name, new_device_key, public_key)
    return {
        'success': True,
        'device_key': new_device_key,
        'project_id': project_id,
        'device_id': iot_device.num_id,
        'topic': iot_device.name,
        'line_notify_access_token': None,
    }


def create_iot_device(new_device_key, public_key):
    return {
        'id': new_device_key,
        'credentials': [
            {
                'public_key': {
                    'format': 'RSA_PEM',
                    'key': public_key
                }
            }
        ]
    }


# noinspection PyUnusedLocal
def receive_states(payload):
    pass


def receive_events(payload):
    device_key = payload['message']['attributes']['deviceId']
    data = json.loads(base64.b64decode(payload['message']['data']))
    device = storage.get_device(device_key)

    if data['event'] == 'connect':
        line.notify_connected(device)

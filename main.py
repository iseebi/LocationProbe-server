import json
import os

from flask import Flask, request, make_response, jsonify, redirect

import line
import pubsub

app = Flask(__name__)
app.secret_key = os.getenv('SESSION_SECRET_KEY')


@app.route('/v1/devices', methods=['PUT'])
def put_user():
    result = pubsub.create_device(json.loads(request.data))

    response = make_response(jsonify(result))
    response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/v1/devices/<device_key>/connections/line')
def get_line_connection_state(device_key):
    result = line.get_connection_state(request.headers['Authorization'], device_key)

    response = make_response(jsonify(result))
    response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/oauth/line-notify/redirect', methods=['POST'])
def auth_line_notify():
    redirect_uri = line.redirect_auth(request.form)
    if redirect_uri is not None:
        return redirect(redirect_uri, code=302)
    else:
        response = make_response('', 403)
        return response


@app.route('/oauth/line-notify/callback', methods=['POST'])
def auth_callback_line_notify():
    redirect_uri = line.redirect_callback(request.form)
    if redirect_uri is not None:
        return redirect(redirect_uri, code=302)
    else:
        response = make_response('', 403)
        return response


@app.route('/_ah/push-handlers/probe/events', methods=['POST'])
def receive_events():
    pubsub.receive_events(json.loads(request.data))

    response = make_response('', 204)
    response.mimetype = app.config['JSONIFY_MIMETYPE']
    return response


@app.route('/_ah/push-handlers/probe/states', methods=['POST'])
def receive_states():
    pubsub.receive_states(json.loads(request.data))

    response = make_response('', 204)
    response.mimetype = app.config['JSONIFY_MIMETYPE']
    return response


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

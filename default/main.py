import os

from flask import Flask, request, make_response, jsonify, redirect, render_template

app = Flask(__name__)
app.secret_key = os.getenv('SESSION_SECRET_KEY')


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

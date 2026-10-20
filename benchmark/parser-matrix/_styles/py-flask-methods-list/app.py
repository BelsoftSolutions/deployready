from flask import Flask, request

app = Flask(__name__)


@app.route("/submit", methods=["POST"])
def submit():
    return request.get_json()

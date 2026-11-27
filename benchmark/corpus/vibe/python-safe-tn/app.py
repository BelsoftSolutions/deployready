import os
import sqlite3
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]


@app.route("/users")
def users():
    name = request.args.get("name", "")
    cur = sqlite3.connect("app.db").execute("SELECT id, name FROM users WHERE name = ?", (name,))
    return jsonify(cur.fetchall())


@app.route("/sync")
def sync():
    return jsonify(requests.get("https://partner.example.com/data", timeout=10).json())


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")

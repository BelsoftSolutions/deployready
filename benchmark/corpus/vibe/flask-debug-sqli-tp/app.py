import sqlite3
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key-123"


def get_db():
    return sqlite3.connect("app.db")


@app.route("/users")
def users():
    name = request.args.get("name", "")
    cur = get_db().execute(f"SELECT id, name FROM users WHERE name = '{name}'")
    return jsonify(cur.fetchall())


@app.route("/sync")
def sync():
    r = requests.get("https://partner.example.com/data", verify=False)
    return jsonify(r.json())


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)

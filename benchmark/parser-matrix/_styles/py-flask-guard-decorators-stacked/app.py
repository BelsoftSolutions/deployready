from flask import Flask
from flask_jwt_extended import jwt_required

from auth import admin_required, login_required

app = Flask(__name__)


@app.route("/admin")
@admin_required
def admin():
    return "ok"


@app.route("/me")
@jwt_required()
def me():
    return "ok"


@app.route("/feed")
@jwt_required(optional=True)
def feed():
    return "ok"


@app.route("/open")
@cache.cached(timeout=50)
def open_page():
    return "ok"

from flask import Flask
from flask_login import login_required

app = Flask(__name__)


@app.route("/me")
@login_required
def me():
    return "me"

from flask import Blueprint, Flask, jsonify

app = Flask(__name__)
api = Blueprint("api", __name__, url_prefix="/api")
items = Blueprint("items", __name__)


@items.route("/")
def list_items():
    return jsonify([])


api.register_blueprint(items, url_prefix="/items")
app.register_blueprint(api)

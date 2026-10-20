from flask import Blueprint, jsonify

items_bp = Blueprint("items", __name__)


@items_bp.route("/items")
def list_items():
    return jsonify([])

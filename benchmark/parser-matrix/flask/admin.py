from flask import Blueprint, jsonify

from auth import admin_required

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/stats")
@admin_required
def stats():
    return jsonify({"users": 0})


@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    return "", 204

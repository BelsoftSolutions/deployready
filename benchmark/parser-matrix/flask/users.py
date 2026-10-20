from flask import Blueprint, jsonify, request

from auth import login_required

users_bp = Blueprint("users", __name__)


@users_bp.route("/")
def list_users():
    return jsonify([])


@users_bp.route("/<int:user_id>")
def get_user(user_id):
    return jsonify({"id": user_id})


@users_bp.route("/", methods=["POST"])
@login_required
def create_user():
    return jsonify(request.get_json()), 201

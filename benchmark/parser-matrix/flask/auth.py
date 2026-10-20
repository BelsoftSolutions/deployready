from functools import wraps

from flask import abort, request


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not request.headers.get("Authorization"):
            abort(401)
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    return login_required(view)

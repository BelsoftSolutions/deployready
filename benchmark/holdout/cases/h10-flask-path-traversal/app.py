import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
UPLOAD_DIR = "/srv/uploads"


@app.route("/download")
def download():
    name = request.args.get("name", "")
    path = os.path.join(UPLOAD_DIR, name)
    if not os.path.exists(path):
        abort(404)
    return send_file(path)

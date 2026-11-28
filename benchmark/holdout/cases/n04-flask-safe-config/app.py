import os
import yaml
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
UPLOAD_DIR = "/srv/uploads"


@app.route("/api/config/import", methods=["POST"])
def import_config():
    return jsonify(yaml.safe_load(request.data))


@app.route("/download")
def download():
    return send_from_directory(UPLOAD_DIR, secure_filename(request.args.get("name", "")))


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")

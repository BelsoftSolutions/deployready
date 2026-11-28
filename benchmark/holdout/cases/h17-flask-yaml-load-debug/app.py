import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/api/config/import", methods=["POST"])
def import_config():
    cfg = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify(cfg)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)

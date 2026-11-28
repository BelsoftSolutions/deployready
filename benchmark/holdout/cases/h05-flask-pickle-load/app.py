import pickle
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/api/import-session", methods=["POST"])
def import_session():
    state = pickle.loads(request.get_data())
    return jsonify({"keys": list(state.keys())})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

from flask import Flask

app = Flask(__name__)


@app.route(
    "/long",
    methods=["GET"],
)
def long_route():
    return "long"

from flask import Flask

app = Flask(__name__)


def legacy():
    return "legacy"


app.add_url_rule("/legacy", view_func=legacy)

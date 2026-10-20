from flask import Flask

from items import items_bp

app = Flask(__name__)
app.register_blueprint(items_bp, url_prefix="/api")

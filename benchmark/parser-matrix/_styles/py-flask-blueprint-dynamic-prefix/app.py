from flask import Flask

from config import settings
from items import items_bp

app = Flask(__name__)
app.register_blueprint(items_bp, url_prefix=settings.PREFIX)

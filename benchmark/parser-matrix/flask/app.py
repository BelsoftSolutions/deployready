from flask import Flask

from admin import admin_bp
from users import users_bp

app = Flask(__name__)
app.register_blueprint(users_bp, url_prefix="/api/users")
app.register_blueprint(admin_bp, url_prefix="/admin")


@app.route("/")
def index():
    return "ok"


if __name__ == "__main__":
    app.run()

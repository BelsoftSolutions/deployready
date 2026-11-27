import os

from flask import Flask, abort, jsonify, request
from flask_login import current_user, login_required

from models import Note, db

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]


@app.route("/notes")
@login_required
def list_notes():
    return jsonify([n.to_dict() for n in Note.query.filter_by(user_id=current_user.id)])


@app.route("/notes/<int:note_id>")
@login_required
def get_note(note_id):
    note = Note.query.get_or_404(note_id)
    return jsonify(note.to_dict())


@app.route("/notes/<int:note_id>", methods=["DELETE"])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    db.session.delete(note)
    db.session.commit()
    return "", 204

from flask import Blueprint, request, session, jsonify
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
)

from extensions import db
from models import User, Note

bp = Blueprint("api", __name__)


# ─── Auth helpers ─────────────────────────────────────────────────────────────

def get_current_user():
    """Resolve the authenticated user from JWT header or session cookie."""
    # Try JWT first (Authorization: Bearer <token>)
    from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
    try:
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
        if identity:
            return User.query.get(identity)
    except Exception:
        pass

    # Fall back to session
    user_id = session.get("user_id")
    if user_id:
        return User.query.get(user_id)

    return None


# ─── Signup ───────────────────────────────────────────────────────────────────

@bp.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")
    password_confirmation = data.get("password_confirmation", "")

    errors = []
    if not username:
        errors.append("Username is required")
    if not password:
        errors.append("Password is required")
    if not password_confirmation:
        errors.append("Password confirmation is required")
    if errors:
        return jsonify({"errors": errors}), 422

    if password != password_confirmation:
        return jsonify({"errors": ["Passwords must match"]}), 422

    if User.query.filter_by(username=username).first():
        return jsonify({"errors": ["Username already taken"]}), 422

    user = User(username=username)
    user.password = password
    db.session.add(user)
    db.session.commit()

    # Return JWT response if Authorization header is expected (JWT client),
    # otherwise fall back to session response.
    # We support both: always set the session AND return a token.
    session["user_id"] = user.id
    token = create_access_token(identity=user.id)

    return jsonify({"token": token, "user": user.to_dict()}), 201


# ─── Login ────────────────────────────────────────────────────────────────────

@bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"errors": ["Username and password are required"]}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.authenticate(password):
        return jsonify({"errors": ["Invalid username or password"]}), 401

    session["user_id"] = user.id
    token = create_access_token(identity=user.id)

    return jsonify({"token": token, "user": user.to_dict()}), 200


# ─── Logout (sessions client) ─────────────────────────────────────────────────

@bp.route("/logout", methods=["DELETE"])
def logout():
    if "user_id" not in session:
        return jsonify({"errors": ["Not logged in"]}), 401
    session.pop("user_id", None)
    return "", 204


# ─── Check session (sessions client) ─────────────────────────────────────────

@bp.route("/check_session", methods=["GET"])
def check_session():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"errors": ["Not authenticated"]}), 401
    user = User.query.get(user_id)
    if not user:
        return jsonify({"errors": ["Not authenticated"]}), 401
    return jsonify(user.to_dict()), 200


# ─── Me (JWT client) ──────────────────────────────────────────────────────────

@bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"errors": ["Not authenticated"]}), 401
    return jsonify(user.to_dict()), 200


# ─── Notes ────────────────────────────────────────────────────────────────────

@bp.route("/notes", methods=["GET"])
def notes_index():
    user = get_current_user()
    if not user:
        return jsonify({"errors": ["Not authenticated"]}), 401

    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 10))
    except ValueError:
        return jsonify({"errors": ["page and per_page must be integers"]}), 422

    if page < 1 or per_page < 1:
        return jsonify({"errors": ["page and per_page must be positive integers"]}), 422
    if per_page > 100:
        return jsonify({"errors": ["per_page cannot exceed 100"]}), 422

    paginated = (
        Note.query
        .filter_by(user_id=user.id)
        .order_by(Note.created_at.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )

    # If page is beyond available pages, return empty notes list
    return jsonify({
        "notes": [n.to_dict() for n in paginated.items],
        "total": paginated.total,
        "page": paginated.page,
        "per_page": paginated.per_page,
        "pages": paginated.pages,
    }), 200


@bp.route("/notes", methods=["POST"])
def create_note():
    user = get_current_user()
    if not user:
        return jsonify({"errors": ["Not authenticated"]}), 401

    data = request.get_json(silent=True) or {}
    title = data.get("title", "").strip()
    body = data.get("body", "").strip()

    errors = []
    if not title:
        errors.append("Title is required")
    if not body:
        errors.append("Body is required")
    if errors:
        return jsonify({"errors": errors}), 422

    note = Note(title=title, body=body, user_id=user.id)
    db.session.add(note)
    db.session.commit()
    return jsonify(note.to_dict()), 201


@bp.route("/notes/<int:note_id>", methods=["GET"])
def get_note(note_id):
    user = get_current_user()
    if not user:
        return jsonify({"errors": ["Not authenticated"]}), 401

    note = Note.query.get(note_id)
    if not note:
        return jsonify({"errors": ["Note not found"]}), 404
    if note.user_id != user.id:
        return jsonify({"errors": ["Forbidden"]}), 403

    return jsonify(note.to_dict()), 200


@bp.route("/notes/<int:note_id>", methods=["PATCH"])
def update_note(note_id):
    user = get_current_user()
    if not user:
        return jsonify({"errors": ["Not authenticated"]}), 401

    note = Note.query.get(note_id)
    if not note:
        return jsonify({"errors": ["Note not found"]}), 404
    if note.user_id != user.id:
        return jsonify({"errors": ["Forbidden"]}), 403

    data = request.get_json(silent=True) or {}
    updated = False
    if "title" in data:
        title = data["title"].strip()
        if not title:
            return jsonify({"errors": ["Title cannot be empty"]}), 422
        note.title = title
        updated = True
    if "body" in data:
        body = data["body"].strip()
        if not body:
            return jsonify({"errors": ["Body cannot be empty"]}), 422
        note.body = body
        updated = True

    if not updated:
        return jsonify({"errors": ["No valid fields provided"]}), 422

    db.session.commit()
    return jsonify(note.to_dict()), 200


@bp.route("/notes/<int:note_id>", methods=["DELETE"])
def delete_note(note_id):
    user = get_current_user()
    if not user:
        return jsonify({"errors": ["Not authenticated"]}), 401

    note = Note.query.get(note_id)
    if not note:
        return jsonify({"errors": ["Note not found"]}), 404
    if note.user_id != user.id:
        return jsonify({"errors": ["Forbidden"]}), 403

    db.session.delete(note)
    db.session.commit()
    return "", 204

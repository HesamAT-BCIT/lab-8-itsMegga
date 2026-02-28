from __future__ import annotations

from typing import Optional, Tuple, Union
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from flask.typing import ResponseReturnValue
import firebase_admin
from firebase_admin import credentials, firestore, auth
from firebase_admin.firestore import DocumentReference
from dotenv import load_dotenv
import os
import requests

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

WEB_API_KEY = os.environ.get("FIREBASE_WEB_API_KEY")

# Initialize Firestore
if not firebase_admin._apps:
    service_account_path = os.getenv("FIREBASE_SERVICE_ACCOUNT", "serviceAccountKey.json")
    cred = credentials.Certificate(service_account_path)
    firebase_admin.initialize_app(cred)
db = firestore.client()

def get_current_user():
    """Return the currently logged-in username (or None).

    Uses session data set during `/login`. This keeps all login checks
    consistent in one place.
    """
    token = session.get("idToken")
    if not token:
        return None
    decoded = auth.verify_id_token(token)
    session["uid"] = decoded.get("uid")
    session["email"] = decoded.get("email")
    return decoded.get("email")


def get_user_or_401():
    """Return the current API user or an Unauthorized response."""
    header = request.headers.get("Authorization")
    if not header or not header.startswith("Bearer "):
        return jsonify({"error": "Invalid token format"}), 401
    token = header.split(" ")[1]
    if not token:
        return None
    try:
        decoded = auth.verify_id_token(token)
        return decoded["uid"], 200
    except Exception as e:
        return jsonify({"error": f"Unauthorized: {str(e)}"}), 401


def get_profile_doc_ref(username: str):
    """Get the Firestore document reference for a user's profile."""
    return db.collection("profiles").document(username)


def get_profile_data(username: str):
    """Fetch a user's profile from Firestore, returning an empty dict if missing."""
    doc = get_profile_doc_ref(username).get()
    return doc.to_dict() if doc.exists else {}


def validate_profile_data(first_name: str, last_name: str, student_id: str):
    """Validate that required profile fields are present and well-formed."""
    if not first_name or not last_name or not student_id:
        return "All fields are required."
    return None


def normalize_profile_data(first_name: str, last_name: str, student_id: str):
    """Normalize profile field values (strip whitespace, stringify student_id)."""
    return {
        "first_name": first_name.strip() if first_name else "",
        "last_name": last_name.strip() if last_name else "",
        "student_id": str(student_id).strip() if student_id else ""
    }


def require_json_content_type():
    """Ensure the request is JSON; returns an error response tuple if not."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    return None


def set_profile(username: str, profile_data: dict[str, str], *, merge: bool):
    """Persist profile data to Firestore.

    Args:
        username: Profile owner.
        profile_data: Data to write.
        merge: When True, merges into existing document (partial update).
    """
    get_profile_doc_ref(username).set(profile_data, merge=merge)

# --- Web Routes ---

@app.route("/")
def home():
    """Home page. Redirects to login if no active session."""
    current_user = get_current_user()
    if current_user:
        return render_template("dashboard.html", username=current_user)
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    email = request.form.get("email")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")

    # Validate passwords match
    if password != confirm_password:
        return render_template("signup.html", error="Passwords do not match"), 400

    # Create user with Firebase Admin SDK
    try:
        user = auth.create_user(email=email, password=password)
    except auth.EmailAlreadyExistsError:
        return render_template("signup.html", error="An account with that email already exists"), 409
    except ValueError:
        return render_template("signup.html", error="Invalid email or password"), 400
    except Exception:
        return render_template("signup.html", error="Could not create account, please try again"), 500
    
    # Initialize profile in Firestore
    try:
        profile_ref = db.collection("users").document(user.uid)
        profile_ref.set({"email": email,
                        "role": "user",
                        "created_at": firestore.SERVER_TIMESTAMP})
    except Exception:
        try:
            auth.delete_user(user.uid)
        except Exception:
            pass
        return render_template("signup.html", error="Could not create account, please try again"), 500
    
    # Redirect to login on success
    return redirect(url_for("login")), 201


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page"""
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("username")
    password = request.form.get("password")

    if not email or not password:
        return render_template("login.html", error="Email and password are required."), 400

    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={WEB_API_KEY}"
    payload = {"email": email, "password": password, "returnSecureToken": True}

    res = requests.post(url, json=payload)
    if res.status_code == 200:
        session["idToken"] = res.json()["idToken"]
        return redirect(url_for("home")), 200
    return render_template("login.html", error="Invalid credentials. Try again."), 401


@app.route("/logout")
def logout():
    """Clear the session and return to login."""
    session.clear()
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
def profile():
    """HTML form to create/update the current user's profile."""
    current_user = get_current_user()
    if not current_user:
        return redirect(url_for("login"))

    if request.method == "GET":
        profile_data = get_profile_data(current_user)
        return render_template("profile.html", profile=profile_data, error=None)

    first_name = request.form.get("first_name", "")
    last_name = request.form.get("last_name", "")
    student_id = request.form.get("student_id", "")

    error = validate_profile_data(first_name, last_name, student_id)
    if error:
        profile_data = {"first_name": first_name, "last_name": last_name, "student_id": student_id}
        return render_template("profile.html", profile=profile_data, error=error)

    normalized = normalize_profile_data(first_name, last_name, student_id)
    set_profile(current_user, normalized, merge=False)
    return redirect(url_for("home"))


# --- API Routes ---

@app.get("/api/profile")
def api_get_profile():
    """Return the current user's profile."""
    user_or_response = get_user_or_401()
    if not isinstance(user_or_response, str):
        return user_or_response

    username = user_or_response
    profile_data = get_profile_data(username)
    return jsonify({"username": username, "profile": profile_data}), 200


@app.post("/api/profile")
def api_create_profile():
    """Create/replace the current user's profile from a JSON body."""
    user_or_response = get_user_or_401()
    if not isinstance(user_or_response, str):
        return user_or_response

    username = user_or_response
    content_error = require_json_content_type()
    if content_error:
        return content_error

    data = request.get_json(silent=True) or {}
    first_name = data.get("first_name", "")
    last_name = data.get("last_name", "")
    student_id = data.get("student_id", "")

    error = validate_profile_data(first_name, last_name, student_id)
    if error:
        return jsonify({"error": error}), 400

    normalized = normalize_profile_data(first_name, last_name, student_id)
    set_profile(username, normalized, merge=False)
    return jsonify({"message": "Profile saved successfully", "profile": normalized}), 200


@app.put("/api/profile")
def api_update_profile():
    """Update the current user's profile from a JSON body."""
    user_or_response = get_user_or_401()
    if not isinstance(user_or_response, str):
        return user_or_response

    username = user_or_response
    content_error = require_json_content_type()
    if content_error:
        return content_error

    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "Request body cannot be empty"}), 400

    first_name = data.get("first_name")
    last_name = data.get("last_name")
    student_id = data.get("student_id")

    # Prepare the update data (only include provided fields)
    update_data = {}
    if first_name is not None:
        update_data["first_name"] = first_name.strip() if first_name else ""
    if last_name is not None:
        update_data["last_name"] = last_name.strip() if last_name else ""
    if student_id is not None:
        update_data["student_id"] = str(student_id).strip() if student_id else ""

    if not update_data:
        return jsonify({"error": "No updatable fields provided"}), 400

    # Merge update into existing document (or create if missing).
    set_profile(username, update_data, merge=True)

    updated_profile = get_profile_data(username)
    return jsonify({"message": "Profile updated successfully", "profile": updated_profile}), 200


@app.delete("/api/profile")
def api_delete_profile():
    """Delete the current user's profile."""
    user_or_response = get_user_or_401()
    if not isinstance(user_or_response, str):
        return user_or_response

    username = user_or_response
    get_profile_doc_ref(username).delete()
    return jsonify({"message": "Profile deleted successfully"}), 200


@app.route("/api/signup", methods=["POST"])
def signup_json():
    email = request.form.get("email")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")

    # Validate passwords match
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    # Create user with Firebase Admin SDK
    try:
        user = auth.create_user(email=email, password=password)
    except auth.EmailAlreadyExistsError:
        return jsonify({"error": "An account with that email already exists"}), 409
    except ValueError:
        return jsonify({"error": "Invalid email or password"}), 400
    except Exception:
        return jsonify({"error": "Could not create account, please try again"}), 500
    
    # Initialize profile in Firestore
    try:
        profile_ref = db.collection("users").document(user.uid)
        profile_ref.set({"email": email,
                        "role": "user",
                        "created_at": firestore.SERVER_TIMESTAMP})
    except Exception:
        try:
            auth.delete_user(user.uid)
        except Exception:
            pass
        return jsonify({"error": "Could not create profile, please try again"}), 500
    
    # Redirect to login on success
    return jsonify({"uid": user.uid, "email": email, "role": "user"}), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={WEB_API_KEY}"
    payload = {"email": data["email"], "password": data["password"], "returnSecureToken": True}

    res = requests.post(url, json=payload)
    if res.status_code == 200:
        return jsonify({"token": res.json()["idToken"]}), 200
    return jsonify({"error": "Invalid credentials"}), 401
if __name__ == "__main__":
    app.run(debug=True, port=5000)

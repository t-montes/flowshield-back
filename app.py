import os, datetime
from urllib.parse import urlencode
from flask import Flask, redirect, request, session, jsonify
from flask_cors import CORS
from flask_session import Session
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from supabase import create_client, Client
from dotenv import load_dotenv
load_dotenv()

os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET"),
    SESSION_TYPE="filesystem",
    SESSION_COOKIE_SAMESITE="Lax",  # localhost:5173 <-> 5000 is same-site
)
Session(app)
CORS(app, supports_credentials=True, origins=[os.getenv("FRONTEND_ORIGIN")])

SUPABASE: Client = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_SERVICE_ROLE_KEY"))

SCOPES = os.getenv("GOOGLE_SCOPES").split()
CLIENT_CONFIG = {
    "web": {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "project_id": "local-dev",
        "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI")],
        "javascript_origins": ["http://localhost:5173", "http://localhost:5000"],
    }
}
REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN")

def upsert_user_and_tokens(google_sub, email, name, picture, creds):
    # Upsert user
    user = (
        SUPABASE.table("app_user")
        .upsert({
            "google_sub": google_sub,
            "email": email,
            "full_name": name,
            "avatar_url": picture,
        }, on_conflict="google_sub")
        .execute()
    ).data[0]

    # Upsert tokens (store refresh_token once we have it)
    SUPABASE.table("google_oauth").upsert({
        "user_id": user["id"],
        "access_token": creds.token,
        "refresh_token": getattr(creds, "refresh_token", None),
        "expiry": creds.expiry.isoformat(),
        "scope": " ".join(creds.scopes or []),
        "token_type": getattr(creds, "token", None) and "Bearer",
        "updated_at": datetime.datetime.utcnow().isoformat()
    }, on_conflict="user_id").execute()

    return user

def load_creds_for_user(user_id):
    row = SUPABASE.table("google_oauth").select("*").eq("user_id", user_id).single().execute().data
    if not row:
        return None
    creds = Credentials(
        token=row["access_token"],
        refresh_token=row["refresh_token"],
        token_uri=CLIENT_CONFIG["web"]["token_uri"],
        client_id=CLIENT_CONFIG["web"]["client_id"],
        client_secret=CLIENT_CONFIG["web"]["client_secret"],
        scopes=(row["scope"] or "").split()
    )
    # Refresh if expired
    if not creds.valid or (creds.expired and creds.refresh_token):
        creds.refresh(google_requests.Request())
        # persist refreshed access token + expiry
        SUPABASE.table("google_oauth").update({
            "access_token": creds.token,
            "expiry": creds.expiry.isoformat(),
            "updated_at": datetime.datetime.utcnow().isoformat()
        }).eq("user_id", user_id).execute()
    return creds

def require_auth(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper

@app.get("/api/auth/google/start")
def google_start():
    flow = Flow.from_client_config(CLIENT_CONFIG, scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"  # ensures refresh_token the first time
    )
    session["oauth_state"] = state
    return redirect(auth_url)

@app.get("/api/auth/google/callback")
def google_callback():
    state = session.get("oauth_state")
    if not state:
        return "Missing state", 400

    flow = Flow.from_client_config(CLIENT_CONFIG, scopes=SCOPES, state=state)
    flow.redirect_uri = REDIRECT_URI
    
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials  # has access_token, refresh_token, expiry, scopes

    # Verify ID token -> user info
    idinfo = google_id_token.verify_oauth2_token(
        creds.id_token, google_requests.Request(), CLIENT_CONFIG["web"]["client_id"]
    )
    google_sub = idinfo["sub"]
    email = idinfo.get("email")
    name = idinfo.get("name", "")
    picture = idinfo.get("picture", "")

    user = upsert_user_and_tokens(google_sub, email, name, picture, creds)
    session["user_id"] = user["id"]

    # Go back to frontend
    return redirect(f"{FRONTEND_ORIGIN}/auth/success")

@app.get("/api/me")
@require_auth
def me():
    # light profile for the UI
    u = SUPABASE.table("app_user").select("id, email, full_name, avatar_url").eq("id", session["user_id"]).single().execute().data
    return jsonify(u)

@app.get("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.get("/api/calendar/events")
@require_auth
def list_events():
    time_min = request.args.get("timeMin")
    time_max = request.args.get("timeMax")
    creds = load_creds_for_user(session["user_id"])
    service = build("calendar", "v3", credentials=creds)
    resp = service.events().list(
        calendarId="primary",
        timeMin=time_min,
        timeMax=time_max,
        singleEvents=True,
        orderBy="startTime"
    ).execute()
    return jsonify(resp.get("items", []))

@app.post("/api/calendar/events")
@require_auth
def create_event():
    body = request.get_json(force=True)
    creds = load_creds_for_user(session["user_id"])
    service = build("calendar", "v3", credentials=creds)
    created = service.events().insert(calendarId="primary", body=body).execute()
    return jsonify(created), 201

if __name__ == "__main__":
    app.run(port=5000, debug=True)

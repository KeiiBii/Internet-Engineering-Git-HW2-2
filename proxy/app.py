import os
import datetime
import jwt
import requests
from flask import Flask, request, Response, jsonify

app = Flask(__name__)

JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-internet-engineering-key-1405")
JWT_ALGORITHM = "HS256"
UPSTREAM_URL = os.getenv("UPSTREAM_URL", "http://127.0.0.1:8081")

EXCLUDED_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}


def verify_jwt_token(auth_header: str):
    if not auth_header:
        return None, "Missing Authorization Header"

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None, "Invalid Authorization Header Format. Expected 'Bearer <token>'"

    token = parts[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, "Token has expired"
    except jwt.InvalidTokenError:
        return None, "Invalid token"


@app.route("/login", methods=["POST"])
def login():
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": "student-user",
        "iat": now,
        "exp": now + datetime.timedelta(hours=2),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return jsonify({"token": token}), 200


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def proxy(path):
    auth_header = request.headers.get("Authorization")
    payload, error = verify_jwt_token(auth_header)
    if error:
        return jsonify({"error": "Unauthorized", "message": error}), 401

    target_url = f"{UPSTREAM_URL}/{path}"

    headers = {
        k: v for k, v in request.headers.items() if k.lower() not in EXCLUDED_HEADERS
    }
    headers["X-Forwarded-For"] = request.remote_addr
    headers["X-Authenticated-User"] = payload.get("sub", "unknown")

    try:
        upstream_response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=request.args,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10,
        )
    except requests.RequestException as exc:
        return jsonify({"error": "Bad Gateway", "details": str(exc)}), 502

    response_headers = [
        (k, v)
        for k, v in upstream_response.raw.headers.items()
        if k.lower() not in EXCLUDED_HEADERS
    ]

    return Response(
        upstream_response.content,
        status=upstream_response.status_code,
        headers=response_headers,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
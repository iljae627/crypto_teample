"""SignVerify 서버 (Flask)

- 공개키 등록: 사용자 계정과 공개키를 묶어 저장 (바꿔치기 방지)
- 문서 서명 제출: 서버가 해시를 다시 계산하고 서명을 검증한 뒤에만 저장
- 문서 검증: 업로드된 문서의 해시를 다시 계산해 저장된 서명과 대조
- 개인키는 절대 서버로 오지 않는다. 서버는 공개키만 가진다.
"""
import base64
import hashlib
import os
import sqlite3
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(BASE_DIR, "signverify.db")

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
ALLOWED_EXT = {".txt", ".md", ".pdf", ".docx", ".hwp", ".png", ".jpg", ".jpeg"}

# 클라이언트(node-forge)와 반드시 같은 파라미터를 써야 검증이 맞는다.
# SHA-256 / MGF1(SHA-256) / salt 32바이트
PSS_PADDING = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)

app = Flask(__name__, static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE + 64 * 1024  # 폼 필드 여유분
app.config["DATABASE"] = os.environ.get("SIGNVERIFY_DB", DEFAULT_DB)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key    TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    filename    TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    signature   TEXT NOT NULL,
    signed_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verify_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL REFERENCES documents(id),
    filename    TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    result      TEXT NOT NULL,
    verified_at TEXT NOT NULL
);
"""


# ---------------------------------------------------------------- DB 헬퍼
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        get_db().executescript(SCHEMA)
        get_db().commit()


def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def error(msg, status=400):
    return jsonify({"ok": False, "error": msg}), status


# ---------------------------------------------------------------- 암호 헬퍼
def load_public_key(pem: str):
    """PEM 공개키를 읽고 RSA 2048비트 이상인지 확인한다."""
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("RSA 공개키만 등록할 수 있습니다.")
    if key.key_size < 2048:
        raise ValueError("2048비트 이상의 키만 허용합니다.")
    return key


def fingerprint(key) -> str:
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def verify_signature(public_key_pem: str, data: bytes, signature: bytes) -> bool:
    """서버 측 재검증: data의 SHA-256을 서버가 직접 계산해 서명과 대조한다."""
    key = load_public_key(public_key_pem)
    try:
        key.verify(signature, data, PSS_PADDING, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def read_upload():
    """업로드 파일 검증 (크기·확장자). (filename, bytes) 또는 에러 응답."""
    f = request.files.get("file")
    if f is None or not f.filename:
        return None, error("파일이 없습니다.")
    filename = os.path.basename(f.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXT:
        return None, error(f"허용되지 않은 형식입니다: {ext or '(없음)'}")
    data = f.read(MAX_FILE_SIZE + 1)
    if len(data) > MAX_FILE_SIZE:
        return None, error("파일은 5MB 이하만 가능합니다.", 413)
    if not data:
        return None, error("빈 파일입니다.")
    return (filename, data), None


def decode_b64(value):
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------- 라우트
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.post("/api/register")
def register():
    """1) 공개키 등록. 같은 사용자명은 다시 등록할 수 없다 (공개키 바꿔치기 방지)."""
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    public_key = body.get("public_key") or ""

    if not (2 <= len(username) <= 30) or not username.replace("_", "").isalnum():
        return error("사용자명은 2~30자의 영문/숫자/_ 만 가능합니다.")
    if len(password) < 8:
        return error("비밀번호는 8자 이상이어야 합니다.")
    try:
        key = load_public_key(public_key)
    except ValueError as e:
        return error(f"공개키 오류: {e}")

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, public_key, key_fingerprint, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (username, generate_password_hash(password), public_key, fingerprint(key), now()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return error("이미 등록된 사용자입니다. 공개키는 교체할 수 없습니다.", 409)

    return jsonify({"ok": True, "username": username, "fingerprint": fingerprint(key)})


@app.get("/api/users/<username>")
def get_user(username):
    row = get_db().execute(
        "SELECT username, public_key, key_fingerprint, created_at FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if row is None:
        return error("사용자를 찾을 수 없습니다.", 404)
    return jsonify({"ok": True, **dict(row)})


@app.post("/api/documents")
def submit_document():
    """2) 서명된 문서 제출.

    클라이언트가 보낸 서명을 그대로 믿지 않고, 서버가 문서 해시를 다시 계산해
    등록된 공개키로 검증한 뒤에만 저장한다.
    """
    upload, err = read_upload()
    if err:
        return err
    filename, data = upload
    username = (request.form.get("username") or "").strip()
    signature = decode_b64(request.form.get("signature") or "")
    if signature is None:
        return error("서명값 형식이 올바르지 않습니다 (base64).")

    db = get_db()
    user = db.execute(
        "SELECT id, public_key FROM users WHERE username = ?", (username,)
    ).fetchone()
    if user is None:
        return error("등록되지 않은 사용자입니다.", 404)

    if not verify_signature(user["public_key"], data, signature):
        return error("서명 검증 실패: 이 사용자의 개인키로 서명된 문서가 아닙니다.", 422)

    digest = hashlib.sha256(data).hexdigest()
    signed_at = now()
    cur = db.execute(
        "INSERT INTO documents (user_id, filename, sha256, signature, signed_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (user["id"], filename, digest, base64.b64encode(signature).decode(), signed_at),
    )
    db.commit()
    return jsonify(
        {
            "ok": True,
            "document_id": cur.lastrowid,
            "filename": filename,
            "sha256": digest,
            "signer": username,
            "signed_at": signed_at,
        }
    )


@app.post("/api/verify")
def verify_document():
    """3) 문서 검증: 문서 ID의 서명으로, 업로드된 파일이 원본과 같은지 확인한다."""
    upload, err = read_upload()
    if err:
        return err
    filename, data = upload
    try:
        document_id = int(request.form.get("document_id", ""))
    except ValueError:
        return error("문서 번호가 올바르지 않습니다.")

    db = get_db()
    doc = db.execute(
        "SELECT d.id, d.filename, d.sha256, d.signature, d.signed_at, u.username, u.public_key"
        " FROM documents d JOIN users u ON u.id = d.user_id WHERE d.id = ?",
        (document_id,),
    ).fetchone()
    if doc is None:
        return error("해당 문서 번호가 없습니다.", 404)

    digest = hashlib.sha256(data).hexdigest()
    valid = verify_signature(doc["public_key"], data, base64.b64decode(doc["signature"]))
    result = "VALID" if valid else "TAMPERED"

    db.execute(
        "INSERT INTO verify_logs (document_id, filename, sha256, result, verified_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (doc["id"], filename, digest, result, now()),
    )
    db.commit()

    return jsonify(
        {
            "ok": True,
            "valid": valid,
            "message": f"원본 일치 (작성자: {doc['username']})" if valid else "위변조 감지",
            "signer": doc["username"],
            "signed_at": doc["signed_at"],
            "original_filename": doc["filename"],
            "original_sha256": doc["sha256"],
            "uploaded_sha256": digest,
        }
    )


@app.get("/api/history")
def history():
    """4) 서명·검증 이력 (언제 누가 서명했고, 언제 검증됐는지)."""
    db = get_db()
    docs = db.execute(
        "SELECT d.id, d.filename, d.sha256, d.signed_at, u.username AS signer"
        " FROM documents d JOIN users u ON u.id = d.user_id ORDER BY d.id DESC LIMIT 50"
    ).fetchall()
    logs = db.execute(
        "SELECT document_id, filename, result, verified_at"
        " FROM verify_logs ORDER BY id DESC LIMIT 50"
    ).fetchall()
    return jsonify(
        {"ok": True, "documents": [dict(r) for r in docs], "verifications": [dict(r) for r in logs]}
    )


@app.post("/api/login")
def login():
    """비밀번호 확인 (확장 기능용). 해시로 저장된 비밀번호와 대조한다."""
    body = request.get_json(silent=True) or {}
    row = get_db().execute(
        "SELECT password_hash FROM users WHERE username = ?", (body.get("username") or "",)
    ).fetchone()
    if row is None or not check_password_hash(row["password_hash"], body.get("password") or ""):
        return error("사용자명 또는 비밀번호가 틀렸습니다.", 401)
    return jsonify({"ok": True})


@app.errorhandler(413)
def too_large(_e):
    return error("파일은 5MB 이하만 가능합니다.", 413)


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

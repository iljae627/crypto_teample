"""위변조 공격 시나리오 테스트 (정량 평가)

실제 서버를 띄우지 않고 Flask 테스트 클라이언트로 API를 호출한다.
클라이언트 서명은 브라우저(node-forge)와 같은 파라미터(SHA-256, MGF1-SHA256, salt 32)로 흉내 낸다.

실행:  python tests/attack_scenarios.py
"""
import base64
import io
import os
import random
import sys
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# 테스트 전용 DB를 쓰도록 app을 import하기 전에 설정
TMP_DB = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["SIGNVERIFY_DB"] = TMP_DB
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8")  # Windows 콘솔에서 한글 깨짐 방지
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
TRIALS = 100
random.seed(2026)
client = app.test_client()


# ---------------------------------------------------------------- 헬퍼
class User:
    def __init__(self, name):
        self.name = name
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @property
    def public_pem(self):
        return self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def sign(self, data: bytes) -> bytes:
        return self.key.sign(data, PSS, hashes.SHA256())


def register(user, public_pem=None):
    return client.post(
        "/api/register",
        json={"username": user.name, "password": "password123", "public_key": public_pem or user.public_pem},
    )


def submit(username, data, signature, filename="contract.txt"):
    return client.post(
        "/api/documents",
        data={
            "username": username,
            "signature": base64.b64encode(signature).decode(),
            "file": (io.BytesIO(data), filename),
        },
        content_type="multipart/form-data",
    )


def verify(doc_id, data, filename="contract.txt"):
    r = client.post(
        "/api/verify",
        data={"document_id": str(doc_id), "file": (io.BytesIO(data), filename)},
        content_type="multipart/form-data",
    )
    return r.get_json()["valid"]


def flip_one_byte(data: bytes) -> bytes:
    pos = random.randrange(len(data))
    b = bytearray(data)
    b[pos] ^= random.randrange(1, 256)  # 반드시 다른 값이 되도록
    return bytes(b)


def flip_one_bit(sig: bytes) -> bytes:
    pos = random.randrange(len(sig) * 8)
    b = bytearray(sig)
    b[pos // 8] ^= 1 << (pos % 8)
    return bytes(b)


# ---------------------------------------------------------------- 준비
alice, mallory = User("alice"), User("mallory")
assert register(alice).status_code == 200
assert register(mallory).status_code == 200

ORIGINAL = (
    "계약서\n갑: 홍길동  을: 김철수\n계약 금액: 1,000,000원\n지급일: 2026년 11월 30일\n".encode("utf-8") * 5
)
r = submit("alice", ORIGINAL, alice.sign(ORIGINAL))
assert r.status_code == 200, r.get_json()
DOC_ID = r.get_json()["document_id"]

results = []  # (시나리오, 시도, 기대대로 처리된 횟수, 설명)


def record(name, trials, passed, desc):
    results.append((name, trials, passed, desc))


# ---------------------------------------------------------------- 시나리오
# 0. 대조군: 원본은 항상 검증 성공해야 한다 (오탐 0%)
ok = sum(verify(DOC_ID, ORIGINAL) for _ in range(10))
record("대조군: 원본 문서 검증", 10, ok, "원본 일치로 판정")

# 1. 문서 1바이트 변조 (무작위 위치)
detected = sum(not verify(DOC_ID, flip_one_byte(ORIGINAL)) for _ in range(TRIALS))
record("1바이트 변조", TRIALS, detected, "위변조 감지")

# 2. 금액 한 글자 수정 (발표 시연용 시나리오)
forged = ORIGINAL.replace("1,000,000원".encode(), "9,000,000원".encode())
record("금액 한 글자 수정", 1, int(not verify(DOC_ID, forged)), "위변조 감지")

# 3. 다른 사용자 사칭: mallory가 자기 키로 서명하고 alice 이름으로 제출
detected = 0
for i in range(TRIALS):
    doc = ORIGINAL + f"\n추가 조항 {i}".encode()
    detected += submit("alice", doc, mallory.sign(doc)).status_code == 422
record("다른 사용자 서명 사칭", TRIALS, detected, "제출 거부 (422)")

# 4. 서명값 1비트 조작
detected = 0
for _ in range(TRIALS):
    detected += submit("alice", ORIGINAL, flip_one_bit(alice.sign(ORIGINAL))).status_code == 422
record("서명값 1비트 조작", TRIALS, detected, "제출 거부 (422)")

# 5. 서명 재사용: alice의 진짜 서명을 다른 문서에 붙여 제출
sig = alice.sign(ORIGINAL)
detected = sum(
    submit("alice", ORIGINAL + f"\n{i}".encode(), sig).status_code == 422 for i in range(TRIALS)
)
record("서명 재사용 (다른 문서에 붙이기)", TRIALS, detected, "제출 거부 (422)")

# 6. 공개키 바꿔치기: mallory가 alice 계정에 자기 공개키를 다시 등록
record("공개키 바꿔치기", 1, int(register(User("alice")).status_code == 409), "등록 거부 (409)")

# 7. 입력 검증: 허용되지 않은 확장자 / 5MB 초과
r1 = submit("alice", b"MZ...", alice.sign(b"MZ..."), filename="malware.exe")
big = b"A" * (5 * 1024 * 1024 + 1)
r2 = submit("alice", big, alice.sign(big))
record("허용 안 된 확장자(.exe)", 1, int(r1.status_code == 400), "업로드 거부 (400)")
record("5MB 초과 파일", 1, int(r2.status_code == 413), "업로드 거부 (413)")

# 8. SQL Injection 시도
r = client.get("/api/users/alice' OR '1'='1")
record("SQL Injection (사용자 조회)", 1, int(r.status_code == 404), "조회 실패 (404)")


# ---------------------------------------------------------------- 결과
print()
print(f"{'시나리오':<32}{'시도':>6}{'통과':>6}{'비율':>9}   기대 결과")
print("-" * 80)
all_pass = True
for name, trials, passed, desc in results:
    rate = passed / trials * 100
    all_pass &= passed == trials
    print(f"{name:<32}{trials:>6}{passed:>6}{rate:>8.1f}%   {desc}")
print("-" * 80)
attack_trials = sum(t for n, t, _, _ in results if not n.startswith("대조군"))
attack_passed = sum(p for n, _, p, _ in results if not n.startswith("대조군"))
print(f"공격 시나리오 전체 감지율: {attack_passed}/{attack_trials} = {attack_passed / attack_trials * 100:.1f}%")
sys.exit(0 if all_pass else 1)

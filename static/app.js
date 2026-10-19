// SignVerify 클라이언트
// 개인키 생성·해시·서명은 모두 브라우저에서 수행하고, 개인키는 서버로 보내지 않는다.

// 서버(Python cryptography)와 반드시 같은 PSS 파라미터: SHA-256 / MGF1(SHA-256) / salt 32바이트
const PSS_SALT_LENGTH = 32;

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------- 화면 공통
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab, .panel").forEach((el) => el.classList.remove("active"));
    btn.classList.add("active");
    $(btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "history") loadHistory();
  });
});

function show(el, kind, html) {
  el.className = `result ${kind}`;
  el.innerHTML = html;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function api(path, options) {
  const res = await fetch(path, options);
  const body = await res.json().catch(() => ({ ok: false, error: `서버 오류 (${res.status})` }));
  if (!body.ok) throw new Error(body.error || "요청 실패");
  return body;
}

function downloadText(filename, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/x-pem-file" }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ---------------------------------------------------------------- 암호 헬퍼
// 파일을 node-forge가 쓰는 바이너리 문자열로 변환
async function fileToBinaryString(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let out = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return out;
}

function generateKeyPair() {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 }, (err, keypair) =>
      err ? reject(err) : resolve(keypair)
    );
  });
}

// 암호화된 개인키 PEM 복호화. 비밀번호가 틀리면 forge가 null을 주거나 예외를 던진다.
function loadPrivateKey(pem, password) {
  let key = null;
  try {
    key = forge.pki.decryptRsaPrivateKey(pem, password);
  } catch (_) {
    key = null;
  }
  if (!key) throw new Error("개인키를 열 수 없습니다. 비밀번호 또는 키 파일을 확인하세요.");
  return key;
}

// SHA-256 해시 → RSA-PSS 서명. 반환: { hashHex, signatureB64 }
function signDocument(privateKey, binary) {
  const md = forge.md.sha256.create();
  md.update(binary);
  const hashHex = md.digest().toHex();

  const pss = forge.pss.create({
    md: forge.md.sha256.create(),
    mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
    saltLength: PSS_SALT_LENGTH,
  });
  const signature = privateKey.sign(md, pss);
  return { hashHex, signatureB64: forge.util.encode64(signature) };
}

// ---------------------------------------------------------------- ① 키 생성·등록
$("btn-register").addEventListener("click", async () => {
  const out = $("reg-result");
  const username = $("reg-username").value.trim();
  const password = $("reg-password").value;
  if (!username || password.length < 8) {
    return show(out, "error", "사용자명과 8자 이상의 비밀번호를 입력하세요.");
  }

  try {
    show(out, "info", "RSA 2048비트 키 쌍 생성 중… (수 초 걸릴 수 있습니다)");
    const t0 = performance.now();
    const { publicKey, privateKey } = await generateKeyPair();
    const elapsed = ((performance.now() - t0) / 1000).toFixed(1);

    const publicPem = forge.pki.publicKeyToPem(publicKey);
    const body = await api("/api/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, public_key: publicPem }),
    });

    // 등록에 성공한 뒤에만 개인키를 저장한다 (비밀번호로 암호화된 PEM)
    const encryptedPem = forge.pki.encryptRsaPrivateKey(privateKey, password, { algorithm: "aes256" });
    downloadText(`${username}_private.pem`, encryptedPem);

    show(
      out,
      "success",
      `등록 완료: <b>${escapeHtml(body.username)}</b> (키 생성 ${elapsed}초)<br>
       공개키 지문(SHA-256): <code>${body.fingerprint}</code><br>
       개인키 파일 <b>${escapeHtml(username)}_private.pem</b>이 다운로드되었습니다. 서명할 때 필요하니 잘 보관하세요.`
    );
  } catch (e) {
    show(out, "error", escapeHtml(e.message));
  }
});

// ---------------------------------------------------------------- ② 문서 서명
$("btn-sign").addEventListener("click", async () => {
  const out = $("sign-result");
  const username = $("sign-username").value.trim();
  const keyFile = $("sign-key").files[0];
  const docFile = $("sign-file").files[0];
  const password = $("sign-password").value;
  if (!username || !keyFile || !docFile) {
    return show(out, "error", "사용자명, 개인키 파일, 문서를 모두 선택하세요.");
  }

  try {
    const privateKey = loadPrivateKey(await keyFile.text(), password);

    const binary = await fileToBinaryString(docFile);
    const { hashHex, signatureB64 } = signDocument(privateKey, binary);

    const form = new FormData();
    form.append("username", username);
    form.append("signature", signatureB64);
    form.append("file", docFile);
    const body = await api("/api/documents", { method: "POST", body: form });

    show(
      out,
      "success",
      `서명 완료. <b>문서 번호: ${body.document_id}</b> (검증할 때 사용)<br>
       파일: ${escapeHtml(body.filename)} · 서명 시각: ${escapeHtml(body.signed_at)}<br>
       브라우저 SHA-256: <code>${hashHex}</code><br>
       서버 SHA-256:&nbsp;&nbsp;&nbsp;&nbsp; <code>${body.sha256}</code>`
    );
  } catch (e) {
    show(out, "error", escapeHtml(e.message));
  }
});

// ---------------------------------------------------------------- ③ 문서 검증
$("btn-verify").addEventListener("click", async () => {
  const out = $("verify-result");
  const id = $("verify-id").value;
  const file = $("verify-file").files[0];
  if (!id || !file) return show(out, "error", "문서 번호와 파일을 입력하세요.");

  try {
    const form = new FormData();
    form.append("document_id", id);
    form.append("file", file);
    const r = await api("/api/verify", { method: "POST", body: form });

    show(
      out,
      r.valid ? "success big" : "error big",
      `<div class="verdict">${r.valid ? "✅" : "❌"} ${escapeHtml(r.message)}</div>
       작성자: ${escapeHtml(r.signer)} · 서명 시각: ${escapeHtml(r.signed_at)}<br>
       원본 SHA-256:&nbsp;&nbsp; <code>${r.original_sha256}</code><br>
       업로드 SHA-256: <code>${r.uploaded_sha256}</code>`
    );
  } catch (e) {
    show(out, "error", escapeHtml(e.message));
  }
});

// ---------------------------------------------------------------- ④ 이력
async function loadHistory() {
  try {
    const r = await api("/api/history");
    $("doc-table").querySelector("tbody").innerHTML = r.documents
      .map(
        (d) => `<tr><td>${d.id}</td><td>${escapeHtml(d.filename)}</td><td>${escapeHtml(d.signer)}</td>
                <td>${escapeHtml(d.signed_at)}</td><td><code>${d.sha256.slice(0, 16)}…</code></td></tr>`
      )
      .join("");
    $("log-table").querySelector("tbody").innerHTML = r.verifications
      .map(
        (v) => `<tr><td>${v.document_id}</td><td>${escapeHtml(v.filename)}</td>
                <td class="${v.result === "VALID" ? "ok" : "bad"}">${v.result === "VALID" ? "원본 일치" : "위변조"}</td>
                <td>${escapeHtml(v.verified_at)}</td></tr>`
      )
      .join("");
  } catch (e) {
    alert(e.message);
  }
}
$("btn-history").addEventListener("click", loadHistory);

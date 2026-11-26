const btn = document.getElementById("go");
const box = document.getElementById("result");
const verdictEl = document.getElementById("verdict");
const iconEl = document.getElementById("verdict-icon");
const labelEl = document.getElementById("verdict-label");
const pctEl = document.getElementById("verdict-pct");
const barEl = document.getElementById("score-bar");
const reasonsEl = document.getElementById("reasons");
const msgEl = document.getElementById("msg");

const imgInput = document.getElementById("img");
const pickBtn = document.getElementById("pick");
const preview = document.getElementById("img-preview");
const thumb = document.getElementById("img-thumb");
const imgRemove = document.getElementById("img-remove");
const ocrStatus = document.getElementById("ocr-status");
const resetBtn = document.getElementById("reset");
const nextSteps = document.getElementById("next-steps");
const shareBtn = document.getElementById("share-card");
let lastResult = null;
const fbRow = document.getElementById("feedback");
const fbQ = document.getElementById("feedback-q");
const fbUp = document.getElementById("fb-up");
const fbDown = document.getElementById("fb-down");

let lastCheck = null; // {verdict, score, source, text} for feedback
let fbSent = false;

const LABELS = {
  safe: "آمن غالبًا",
  suspicious: "مشبوه، خد بالك",
  scam: "نصب، متتعاملش معاه",
};
const ICONS = { safe: "✓", suspicious: "!", scam: "✕" };

function setLoading(on) {
  btn.disabled = on;
  btn.classList.toggle("loading", on);
  btn.querySelector(".btn-text").textContent = on ? "بيفحص..." : "افحص دلوقتي";
}

function showVerdict(kind, score, reasons) {
  box.className = "panel result " + kind;
  verdictEl.className = kind;
  iconEl.textContent = ICONS[kind];
  labelEl.textContent = LABELS[kind];
  pctEl.textContent = "نسبة الخطورة " + Math.round(score * 100) + "%";
  barEl.style.width = "0";
  requestAnimationFrame(() => {
    requestAnimationFrame(() => { barEl.style.width = Math.round(score * 100) + "%"; });
  });
  reasonsEl.innerHTML = "";
  for (const r of reasons) {
    const li = document.createElement("li");
    li.textContent = r;
    reasonsEl.appendChild(li);
  }
  lastResult = { kind, score, reasons: reasons.slice(0, 3) };
  nextSteps.classList.toggle("hidden", kind !== "scam");
  fbRow.classList.remove("hidden");
  fbQ.textContent = "النتيجة دي صح؟";
  fbUp.classList.remove("picked");
  fbDown.classList.remove("picked");
  fbSent = false;
  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function sendFeedback(vote) {
  if (fbSent || !lastCheck) return;
  fbSent = true;
  (vote === "up" ? fbUp : fbDown).classList.add("picked");
  fbQ.textContent = "شكرًا! ملاحظتك بتساعد الفحص يتحسن.";
  try {
    await fetch("/api/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        vote,
        verdict: lastCheck.verdict,
        score: lastCheck.score,
        source: lastCheck.source,
        text: lastCheck.text || "",
      }),
    });
  } catch (e) { /* feedback is best-effort */ }
}

fbUp.addEventListener("click", () => sendFeedback("up"));
fbDown.addEventListener("click", () => sendFeedback("down"));

btn.addEventListener("click", async () => {
  const text = msgEl.value.trim();
  if (!text) return;
  setLoading(true);
  try {
    const resp = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      showVerdict("suspicious", 0.5, [data.error === "too_long" ? "الرسالة طويلة أوي، قصّرها وجرب تاني" : "حصل خطأ غير متوقع، جرب تاني"]);
    } else {
      showVerdict(data.verdict, data.score, data.reasons);
      lastCheck = { verdict: data.verdict, score: data.score, source: "text", text };
    }
  } catch (e) {
    showVerdict("suspicious", 0.5, ["مش قادر أوصل للخادم، اتأكد إن البرنامج شغال وجرب تاني"]);
  }
  setLoading(false);
});

msgEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) btn.click();
});

/* ---------- screenshot OCR (in-browser, nothing uploaded to the server) ---------- */

let ocrWorker = null;
let ocrBusy = false;

function setOcrStatus(text, cls) {
  ocrStatus.textContent = text || "";
  ocrStatus.className = cls || (text ? "" : "hidden");
  if (!text) ocrStatus.classList.add("hidden");
}

// Tesseract reads small Latin URLs/@handles in Arabic screenshots as runs of
// zeros ("0000:0000-000.000"). Detect that shape so we can warn the user that
// a link was mangled instead of silently checking a blind text.
function hasMangledLink(text) {
  const tokens = text.match(/[0O0-9:.\-/]{8,}/g) || [];
  for (const t of tokens) {
    const zeros = (t.match(/[0O]/g) || []).length;
    if (zeros / t.length >= 0.6 && /[:.\-]/.test(t)) return true;
  }
  return false;
}

async function getOcrWorker() {
  if (ocrWorker) return ocrWorker;
  setOcrStatus("بنجهز قارئ الصور أول مرة...", "");
  await new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js";
    s.onload = resolve;
    s.onerror = () => reject(new Error("cdn"));
    document.head.appendChild(s);
  });
  ocrWorker = await Tesseract.createWorker("ara+eng", 1, {
    logger: (m) => {
      if (m.status === "recognizing text") {
        setOcrStatus("بيقرأ الصورة... " + Math.round(m.progress * 100) + "%", "");
      }
    },
  });
  return ocrWorker;
}

pickBtn.addEventListener("click", () => { if (!ocrBusy) imgInput.click(); });

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(",")[1] || "");
    r.onerror = () => reject(new Error("read"));
    r.readAsDataURL(file);
  });
}

// Server-side vision: image in, verdict out, no text is ever shown.
// Returns the verdict object, or null when the server has no vision key
// (503) so the caller falls back to in-browser OCR.
async function checkImageServerSide(file) {
  const b64 = await fileToBase64(file);
  const resp = await fetch("/api/check-image", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ image: b64, mime: file.type || "image/png" }),
  });
  if (resp.status === 503) return null;
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    if (data.error === "no_text") return { noText: true };
    throw new Error("server");
  }
  return data;
}

async function processImage(file) {
  thumb.src = URL.createObjectURL(file);
  preview.classList.remove("hidden");
  ocrBusy = true;
  pickBtn.disabled = true;

  // Preferred path: the server reads the screenshot and returns the verdict
  // directly. The extracted text never reaches the page.
  try {
    setOcrStatus("بيفحص الصورة...", "");
    const data = await checkImageServerSide(file);
    if (data && !data.noText) {
      setOcrStatus("", "");
      showVerdict(data.verdict, data.score, data.reasons);
      lastCheck = { verdict: data.verdict, score: data.score, source: "image", text: "" };
      ocrBusy = false;
      pickBtn.disabled = false;
      return;
    }
    if (data && data.noText) {
      setOcrStatus("مقدرناش نلاقي نص واضح في الصورة. جرب سكرينشوت أوضح أو اكتب الرسالة بنفسك.", "err");
      ocrBusy = false;
      pickBtn.disabled = false;
      return;
    }
    // data === null: server has no vision key, fall through to in-browser OCR.
  } catch (e) {
    // Server path failed, fall through to in-browser OCR.
  }

  try {
    const worker = await getOcrWorker();
    const { data } = await worker.recognize(file);
    const text = (data.text || "").trim();
    if (text.length >= 3) {
      // Verdict only: the extracted text is never shown or put in the box.
      const resp = await fetch("/api/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: text.slice(0, 5000) }),
      });
      const res = await resp.json();
      if (!resp.ok) throw new Error("check");
      showVerdict(res.verdict, res.score, res.reasons);
      lastCheck = { verdict: res.verdict, score: res.score, source: "image", text: "" };
      if (hasMangledLink(text)) {
        setOcrStatus("فيه لينك أو حساب في الصورة القراءة مقدرتش تقراه كويس. لو تقدر تنسخ الرسالة نصًا الفحص هيبقى أدق.", "ok");
      } else {
        setOcrStatus("", "");
      }
    } else {
      setOcrStatus("مقدرناش نلاقي نص واضح في الصورة. جرب سكرينشوت أوضح أو اكتب الرسالة بنفسك.", "err");
    }
  } catch (e) {
    setOcrStatus("قراءة الصورة فشلت. اتأكد من النت وجرب تاني، أو اكتب الرسالة بنفسك.", "err");
  }
  ocrBusy = false;
  pickBtn.disabled = false;
}

imgInput.addEventListener("change", () => {
  const file = imgInput.files && imgInput.files[0];
  if (file) processImage(file);
});

imgRemove.addEventListener("click", () => {
  imgInput.value = "";
  preview.classList.add("hidden");
  thumb.removeAttribute("src");
  if (!ocrBusy) setOcrStatus("", "");
});

/* ---------- new analysis ---------- */

resetBtn.addEventListener("click", () => {
  msgEl.value = "";
  imgInput.value = "";
  preview.classList.add("hidden");
  thumb.removeAttribute("src");
  setOcrStatus("", "");
  box.className = "panel result hidden";
  fbRow.classList.add("hidden");
  nextSteps.classList.add("hidden");
  lastCheck = null;
  lastResult = null;
  window.scrollTo({ top: 0, behavior: "smooth" });
  msgEl.focus();
});

/* ---------- share target / prefill + PWA registration ---------- */

(function () {
  const p = new URLSearchParams(location.search);
  const shared = (p.get("text") || "") + " " + (p.get("url") || "");
  if (shared.trim()) {
    msgEl.value = shared.trim().slice(0, 5000);
    history.replaceState(null, "", location.pathname);
  }
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }
})();

/* ---------- share the warning (result card image, made on-device) ---------- */

function wrapLines(ctx, text, maxWidth) {
  const words = text.split(" ");
  const lines = [];
  let cur = "";
  for (const w of words) {
    const t = cur ? cur + " " + w : w;
    if (ctx.measureText(t).width > maxWidth && cur) { lines.push(cur); cur = w; } else { cur = t; }
  }
  if (cur) lines.push(cur);
  return lines;
}

async function buildCard() {
  try { await document.fonts.load("700 40px Tajawal"); await document.fonts.load("400 30px Tajawal"); } catch (e) {}
  const W = 1080, H = 1350;
  const c = document.createElement("canvas");
  c.width = W; c.height = H;
  const x = c.getContext("2d");
  x.direction = "rtl";
  x.textAlign = "center";
  const colors = { safe: "#34d399", suspicious: "#fbbf24", scam: "#f87171" };
  const col = colors[lastResult.kind];
  x.fillStyle = "#0b0f14"; x.fillRect(0, 0, W, H);
  x.fillStyle = col; x.globalAlpha = 0.12; x.fillRect(0, 0, W, 520); x.globalAlpha = 1;
  x.fillStyle = "#8b98a5"; x.font = "700 44px Tajawal, sans-serif";
  x.fillText("فاحص", W / 2, 110);
  x.fillStyle = col; x.font = "800 150px Tajawal, sans-serif";
  x.fillText({ safe: "✓", suspicious: "!", scam: "✕" }[lastResult.kind], W / 2, 300);
  x.fillStyle = "#e8eef4"; x.font = "800 72px Tajawal, sans-serif";
  const title = lastResult.kind === "scam" ? "رسالة نصب" : lastResult.kind === "suspicious" ? "رسالة مشبوهة" : "آمنة غالبًا";
  x.fillText(title, W / 2, 410);
  x.fillStyle = col; x.font = "700 46px Tajawal, sans-serif";
  x.fillText("نسبة الخطورة " + Math.round(lastResult.score * 100) + "%", W / 2, 480);
  // bar
  x.fillStyle = "#1f2a35"; x.fillRect(140, 530, 800, 18);
  x.fillStyle = col; x.fillRect(140 + 800 * (1 - lastResult.score), 530, 800 * lastResult.score, 18);
  // reasons (generic wording from the checker, never the message itself)
  x.fillStyle = "#e8eef4"; x.font = "500 38px Tajawal, sans-serif";
  let y = 640;
  for (const r of lastResult.reasons) {
    for (const line of wrapLines(x, "• " + r, 860).slice(0, 3)) { x.fillText(line, W / 2, y); y += 62; }
    y += 18;
    if (y > 1050) break;
  }
  x.fillStyle = "#f87171"; x.font = "700 40px Tajawal, sans-serif";
  if (lastResult.kind === "scam") x.fillText("متدوسش على اللينك ومتبعتش بيانات", W / 2, 1150);
  x.fillStyle = "#8b98a5"; x.font = "400 34px Tajawal, sans-serif";
  x.fillText("اكشف أي رسالة على " + location.host, W / 2, 1260);
  return new Promise((res) => c.toBlob(res, "image/png"));
}

shareBtn.addEventListener("click", async () => {
  if (!lastResult) return;
  shareBtn.disabled = true;
  try {
    const blob = await buildCard();
    const file = new File([blob], "fahes-warning.png", { type: "image/png" });
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      await navigator.share({ files: [file], text: "اتحققت من رسالة بفاحص" });
    } else {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "fahes-warning.png";
      a.click();
    }
  } catch (e) { /* user cancelled share */ }
  shareBtn.disabled = false;
});

/* ---------- image shared from the phone share sheet ---------- */

(async function () {
  const p = new URLSearchParams(location.search);
  if (p.get("shared") !== "image" || !("caches" in window)) return;
  history.replaceState(null, "", location.pathname);
  try {
    const cache = await caches.open("shared");
    const resp = await cache.match("/shared-image");
    if (!resp) return;
    const blob = await resp.blob();
    await cache.delete("/shared-image");
    await processImage(new File([blob], "shared", { type: blob.type || "image/png" }));
  } catch (e) {}
})();

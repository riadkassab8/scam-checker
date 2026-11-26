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

imgInput.addEventListener("change", async () => {
  const file = imgInput.files && imgInput.files[0];
  if (!file) return;
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
      msgEl.value = msgEl.value.trim() ? msgEl.value.trim() + "\n" + text : text;
      let note = "استخرجنا النص من الصورة وفضلناه في الخانة فوق. راجعه كويس - القراءة الآلية ممكن تغلط في كلمة أو اتنين - وبعدين اضغط افحص.";
      if (hasMangledLink(text)) {
        note += " فيه ما يبدو إنه لينك أو حساب في الصورة بس القراءة شوّهته وظهر كأصفار - لو تقدر تنسخ الرسالة نصًا، الفحص هيبقى أدق.";
      }
      setOcrStatus(note, "ok");
      msgEl.focus();
    } else {
      setOcrStatus("مقدرناش نلاقي نص واضح في الصورة. جرب سكرينشوت أوضح أو اكتب الرسالة بنفسك.", "err");
    }
  } catch (e) {
    setOcrStatus("قراءة الصورة فشلت. اتأكد من النت وجرب تاني، أو اكتب الرسالة بنفسك.", "err");
  }
  ocrBusy = false;
  pickBtn.disabled = false;
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
  lastCheck = null;
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
    navigator.serviceWorker.register("/static/sw.js").catch(() => {});
  }
})();

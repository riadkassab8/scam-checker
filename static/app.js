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
  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

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

imgInput.addEventListener("change", async () => {
  const file = imgInput.files && imgInput.files[0];
  if (!file) return;
  thumb.src = URL.createObjectURL(file);
  preview.classList.remove("hidden");
  ocrBusy = true;
  pickBtn.disabled = true;
  try {
    const worker = await getOcrWorker();
    const { data } = await worker.recognize(file);
    const text = (data.text || "").trim();
    if (text.length >= 3) {
      msgEl.value = msgEl.value.trim() ? msgEl.value.trim() + "\n" + text : text;
      setOcrStatus("استخرجنا النص من الصورة وفضلناه في الخانة فوق. راجعه كويس - القراءة الآلية ممكن تغلط في كلمة أو اتنين - وبعدين اضغط افحص.", "ok");
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
  window.scrollTo({ top: 0, behavior: "smooth" });
  msgEl.focus();
});

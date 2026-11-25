const btn = document.getElementById("go");
const box = document.getElementById("result");
const verdictEl = document.getElementById("verdict");
const iconEl = document.getElementById("verdict-icon");
const labelEl = document.getElementById("verdict-label");
const pctEl = document.getElementById("verdict-pct");
const barEl = document.getElementById("score-bar");
const reasonsEl = document.getElementById("reasons");

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
  const text = document.getElementById("msg").value.trim();
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

document.getElementById("msg").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) btn.click();
});

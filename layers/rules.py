"""Layer 1: direct rules. Fast checks on URLs and message text.

Built from a worldwide survey of scam tactics (see RESEARCH.md): bank and
government impersonation, delivery/customs fees, prizes, job/task scams,
crypto investment lures, "hey mum" family impersonation, gift-card and OTP
requests, tech-support scare tactics.

Each rule hit returns (score, arabic_reason). The layer combines hits into
one score in [0, 1] plus human-readable reasons.
"""

import os
import re
from urllib.parse import urlparse

try:
    import tldextract
except ImportError:  # pragma: no cover
    tldextract = None

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

URL_RE = re.compile(r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(?:com|net|org|info|xyz|top|site|online|link|click|me|ly|io|co|store|shop)(?:/[^\s]*)?)", re.IGNORECASE)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "t.ly", "rebrand.ly", "ow.ly", "buff.ly", "adf.ly",
    "bitly.com", "tiny.cc", "s.id", "jrni.com",
}

IMPERSONATED_BRANDS = [
    "vodafone", "فودافون", "etisalat", "اتصالات", "orange", "اورانج",
    "we", "banque", "بنك", "مصرف", "البنك", "cib", "nbk", "alahli", "الاهلي",
    "الأهلي", "qnb", "rajhi", "الراجحي", "misr", "مصر", "amazon", "امازون",
    "أمازون", "paypal", "netflix", "facebook", "فيسبوك", "whatsapp", "واتساب",
    "instagram", "انستجرام", "telegram", "تليجرام", "visa", "فيزا",
    "mastercard", "fawry", "فوري", "instapay", "انستاباي", "mpesa", "m-pesa",
    "hsbc", "barclays", "chase", "wellsfargo", "lloyds", "dhl", "fedex",
    "usps", "royalmail", "correos", "evri", "binance", "باينانس",
]

TRUSTED_DOMAINS = {
    "vodafone.com.eg", "etisalat.eg", "orange.eg", "te.eg", "we.eg",
    "banquemisr.com", "cibeg.com", "nbe.com.eg", "alahly.com", "qnbalahli.com",
    "egyptpost.gov.eg", "fawry.com", "instapay.eg", "amazon.eg", "amazon.com",
    "booking.com", "google.com", "facebook.com", "whatsapp.com", "instagram.com",
    "youtube.com", "twitter.com", "x.com", "linkedin.com", "microsoft.com",
    "apple.com", "netflix.com", "paypal.com", "gov.eg", "dhl.com", "fedex.com",
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".link", ".online", ".site", ".icu", ".live", ".buzz", ".rest"}

# text categories: (key, score, reason, patterns)
CATEGORIES = [
    ("threat_lock", 0.55,
     "الرسالة بتهدد بإيقاف أو حظر الحساب، وأسلوب التهديد ده علامة نصب معروفة",
     [r"تم\s*(ايقاف|إيقاف|تعليق|حظر|قفل)\s*(حساب|الحساب|حسابك)",
      r"حسابك\s*(تم|سيتم)?\s*(ايقاف|إيقاف|تعليق|حظر|قفل|إغلاق|اغلاق)",
      r"سيتم\s*(ايقاف|إيقاف|تعليق|حظر|قفل|إغلاق|اغلاق)",
      r"إغلاق\s*!!", r"حظر\s*نهائي", r"تجميد",
      r"suspend", r"blocked", r"locked", r"deactivat",
      r"unusual\s*activity", r"suspicious\s*activity",
      r"تم رصد نشاط", r"محاولة دخول"]),
    ("credential", 0.6,
     "الرسالة بتطلب بيانات حساسة زي كلمة السر أو بيانات البطاقة، والجهات الرسمية مش بتطلب كده أبدا",
     [r"رقم\s*ال(card|كارت|بطاقة)", r"بيانات\s*(الحساب|البطاقة|الكارت)",
      r"الرقم\s*السري", r"كلمة\s*(السر|المرور)", r"\bcvv\b", r"رقم\s*سري",
      r"أرسل\s*بياناتك", r"حدث\s*بياناتك", r"تحديث\s*البيانات", r"تفعيل\s*الحساب",
      r"password", r"card\s*number", r"security\s*code",
      r"online\s*banking", r"verify\s*your\s*(account|identity)",
      r"confirm\s*your\s*(account|identity|details)"]),
    ("otp_forward", 0.65,
     "الرسالة بتطلب كود التحقق اللي وصلك، وده أخطر أسلوب سرقة حسابات: الكود ده ملكك لوحدك",
     [r"ابعت\s*الكود", r"ارسل\s*الكود", r"اكتب\s*الكود",
      r"الكود\s*اللي\s*(وصلك|جالك|اتبعت)", r"رمز\s*التحقق", r"رمز\s*التفعيل",
      r"\botp\b", r"one.?time\s*(pass)?code", r"send\s*(me\s*)?the\s*code",
      r"share\s*the\s*code", r"verification\s*code", r"كود\s*التحقق"]),
    ("prize", 0.5,
     "الرسالة بتقول إنك كسبت جائزة أو هدية من غير ما تشارك في حاجة",
     [r"(ربحت|فزت|مبروك|تهانينا).{0,40}(جائزة|هدية|رصيد|هاتف|ايفون|آيفون|سيارة|مليون)",
      r"(جائزة|هدية)\s*(كبيرة|مجانية|نقدية)", r"قسيمة\s*شراء\s*مجانية", r"يانصيب",
      r"(won|winner|congratulations).{0,50}(prize|gift|iphone|lottery|million)",
      r"free\s*(gift|prize|money)", r"cash\s*prize", r"lottery", r"selected\s*winner"]),
    ("urgency", 0.25,
     "الرسالة بتحاول تستعجلك وتخليك تتصرف بسرعة من غير تفكير",
     [r"خلال\s*24", r"خلال\s*48", r"فورا", r"فوراً", r"حالا", r"حالاً",
      r"الان\b", r"الآن\b", r"دلوقتي", r"عاجل", r"اخر\s*فرصة", r"آخر\s*فرصة",
      r"قبل\s*فوات", r"ينتهي\s*(اليوم|العرض)", r"عرض\s*محدود", r"لفترة\s*محدودة",
      r"urgent", r"immediately", r"within\s*24", r"within\s*48",
      r"expires?\s*today", r"last\s*chance", r"act\s*now", r"limited\s*time"]),
    ("advance_fee", 0.45,
     "الرسالة بتطلب فلوس أو رسوم مقدمة، وده قلب أسلوب النصب بالرسوم",
     [r"(ادفع|ادفعي|سدد|سداد|حوّ?ل\s+(مبلغ|رسوم|الفلوس)|رسوم\s*(الشحن|التخليص|الإفراج|التوصيل|الجمارك)|عربون)",
      r"customs?\s*fee", r"clearance\s*fee", r"delivery\s*fee", r"shipping\s*fee",
      r"processing\s*fee", r"transfer\s*fee", r"small\s*fee", r"redelivery",
      r"مصاريف\s*الشحن", r"ضريبة", r"import\s*duty"]),
    ("crypto_investment", 0.5,
     "الرسالة بتعرض استثمار أو أرباح مضمونة في كريبتو أو تداول، ودي أشهر خدعة استثمار في العالم",
     [r"استثمر", r"منصة\s*استثمار", r"ارباح\s*يومية", r"أرباح\s*يومية", r"عوائد\s*مضمونة",
      r"bitcoin", r"بيتكوين", r"crypto", r"كريبتو", r"\busdt\b", r"tether",
      r"binance", r"باينانس", r"forex", r"فوركس", r"تداول",
      r"guaranteed\s*(returns|profit)", r"double\s*your\s*money",
      r"investment\s*opportunity", r"daily\s*profit", r"trading\s*platform"]),
    ("job_scam", 0.45,
     "عرض شغل سهل بفلوس كتير من غير مقابلة ولا خبرة، وده أسلوب نصب وظائف منتشر",
     [r"وظيفة.{0,30}(راتب|دخل|بيت)", r"شغل\s*من\s*البيت", r"راتب\s*يومي",
      r"بدون\s*خبرة", r"مهام\s*بسيطة", r"عمولة\s*يومية",
      r"work\s*from\s*home", r"no\s*experience\s*(needed|required)",
      r"daily\s*(income|payment)", r"easy\s*money", r"hiring\s*immediately",
      r"part.?time\s*job", r"like\s*and\s*(subscribe|earn)", r"earn\s*\$\d+.*(day|daily)"]),
    ("gov_fine", 0.55,
     "الرسالة بتنتحل جهة حكومية أو قانونية بغرامة أو إجراء، والجهات الرسمية مش بتطلب دفع برسايل",
     [r"غرامة", r"مخالفة\s*(مرورية|مرور)", r"استرداد\s*ضريبي", r"منحة\s*حكومية",
      r"محكمة", r"مذكرة\s*(اعتقال|قبض)",
      r"traffic\s*(fine|violation)", r"tax\s*refund", r"\birs\b", r"court\s*(order|summons)",
      r"arrest\s*warrant", r"legal\s*action", r"police\s*(report|notice)",
      r"outstanding\s*debt", r"bailiff"]),
    ("hey_mum", 0.55,
     "رسالة 'أنا ابنك وده رقمي الجديد' من أشهر خدع واتساب في العالم: أكد من الرقم القديم الأول",
     [r"(ماما|بابا).{0,40}(رقمي\s*الجديد|تليفوني|موبايلي)",
      r"رقمي\s*الجديد", r"تليفوني\s*(اتكسر|ضاع|باظ)",
      r"(mum|mom|dad).{0,40}(new\s*number|new\s*phone)",
      r"my\s*(new\s*number|phone\s*(broke|is\s*broken|died))",
      r"lost\s*my\s*phone", r"hola\s*(mama|papa)"]),
    ("gift_card", 0.55,
     "طلب بطايق هدايا أو كروت شحن علامة نصب شبه مؤكدة: محدش حقيقي بيطلب فلوس بالطريقة دي",
     [r"gift\s*card", r"itunes", r"google\s*play\s*(card|gift)", r"steam\s*(card|wallet)",
      r"voucher\s*code", r"بطاقة\s*هدايا", r"بطاقات\s*هدايا", r"كارت\s*شحن", r"كروت\s*شحن",
      r"رصيد\s*(كارت|شحن)"]),
    ("tech_support", 0.6,
     "تحذير فيروسات أو دعم فني وهمي: مايكروسوفت وآبل مش بيكلموا حد برسايل ولا بيطلبوا فلوس",
     [r"virus\s*(detected|alert|warning)", r"malware\s*detected",
      r"microsoft\s*(support|technician)", r"apple\s*support", r"windows\s*(support|defender)\s*(alert)?",
      r"technical\s*(support|department)", r"call\s*(this\s*number|support)\s*(now|immediately)?",
      r"جهازك\s*(مصاب|فيه\s*فيروس)", r"فيروس", r"الدعم\s*الفني"]),
]

# path words that mean "give me your login" when the domain is not the brand
LOGIN_PATH_WORDS = re.compile(r"(login|signin|verify|verification|secure|update|confirm|account|billing|wallet|activate|unlock|recover)", re.IGNORECASE)


def _load_phish_domains():
    path = os.path.join(DATA_DIR, "known_phish_domains.txt")
    try:
        with open(path, encoding="utf-8") as f:
            return {l.strip().lower() for l in f if l.strip()}
    except OSError:
        return set()


PHISH_DOMAINS = _load_phish_domains()


def extract_urls(text):
    return URL_RE.findall(text)


def _host_of(url):
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _registrable(host):
    if tldextract is not None:
        ext = tldextract.extract(host)
        return ".".join(p for p in (ext.domain, ext.suffix) if p)
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def check_urls(text):
    hits = []
    urls = extract_urls(text)
    for url in urls:
        host = _host_of(url)
        if not host:
            continue
        reg = _registrable(host)
        if host in PHISH_DOMAINS or reg in PHISH_DOMAINS:
            hits.append((0.95, "الرابط ده مسجل في قايمة OpenPhish كرابط تصيد معروف"))
            continue
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d+)?", host):
            hits.append((0.85, "الرابط بيستخدم عنوان IP مباشر بدل اسم موقع، وده تصرف مشبوه"))
        if "@" in url:
            hits.append((0.7, "الرابط فيه علامة @، وده تمويه بيخلي المتصفح يروح لموقع مختلف عن المكتوب"))
        if reg in SHORTENERS:
            hits.append((0.45, "الرابط مختصر بخدمة تقصير روابط، ومش باين وجهته الحقيقية"))
        if host.startswith("xn--") or ".xn--" in host:
            hits.append((0.8, "الرابط بيستخدم حروف مشفرة (punycode) ممكن تقلد موقع تاني"))
        if host.count(".") >= 4:
            hits.append((0.4, "الرابط فيه مستويات دومين كتير، وده تمويه شائع في روابط التصيد"))
        tld = "." + host.split(".")[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            hits.append((0.3, f"امتداد الموقع ({tld}) من الامتدادات اللي بتستخدم كتير في النصب"))
        domain_part = reg.split(".")[0] if "." in reg else reg
        if domain_part.count("-") >= 2 or (re.search(r"\d{3,}", domain_part) and reg not in TRUSTED_DOMAINS):
            hits.append((0.25, "اسم الموقع نفسه شكله مصطنع (شرطات أو أرقام كتير)"))
        if len(url) > 75:
            hits.append((0.2, "الرابط طويل بشكل غير طبيعي، وده بيستر على وجهته الحقيقية"))
        host_ascii = host.replace("-", "").replace(".", "")
        for brand in IMPERSONATED_BRANDS:
            b = brand.replace(" ", "")
            if len(b) < 3 or not b.isascii():
                continue
            if b in host_ascii and b not in reg.replace(".", ""):
                hits.append((0.8, f"الرابط بيحط اسم '{brand}' جوه عنوان موقع تاني، وده تقليد شائع"))
                break
        else:
            if LOGIN_PATH_WORDS.search(url) and reg not in TRUSTED_DOMAINS:
                hits.append((0.35, "الرابط بيطلب تسجيل دخول أو تأكيد بيانات على موقع مش معروف"))
    return urls, hits


def check_text(text):
    hits = []
    lowered = text.lower()
    for _key, score, reason, patterns in CATEGORIES:
        if any(re.search(p, lowered, re.IGNORECASE) for p in patterns):
            hits.append((score, reason))
    return hits


def run(text):
    """Return (score, reasons, urls, all_urls_trusted). Score in [0, 1]."""
    urls, url_hits = check_urls(text)
    text_hits = check_text(text)
    hits = url_hits + text_hits
    trusted_only = bool(urls) and all(_registrable(_host_of(u)) in TRUSTED_DOMAINS for u in urls)
    if not hits:
        return 0.0, [], urls, trusted_only
    scores = sorted((s for s, _ in hits), reverse=True)
    total = scores[0]
    for s in scores[1:]:
        total += s * 0.35 * (1 - total)
    reasons = [r for _, r in hits]
    return min(total, 1.0), reasons, urls, trusted_only

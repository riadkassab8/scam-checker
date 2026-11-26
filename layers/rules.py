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
      r"تم رصد نشاط", r"محاولة دخول",
      r"7esabak", r"hesabak", r"et2af", r"etwa2af", r"7azar\s*7esab"]),
    ("credential", 0.6,
     "الرسالة بتطلب بيانات حساسة زي كلمة السر أو بيانات البطاقة، والجهات الرسمية مش بتطلب كده أبدا",
     [r"رقم\s*ال(card|كارت|بطاقة)", r"بيانات\s*(الحساب|البطاقة|الكارت)",
      r"الرقم\s*السري", r"كلمة\s*(السر|المرور)", r"\bcvv\b", r"رقم\s*سري", r"رقمك\s*السري",
      r"أرسل\s*بياناتك", r"حدث\s*بياناتك", r"تحديث\s*البيانات", r"تفعيل\s*الحساب",
      r"password", r"card\s*number", r"security\s*code",
      r"online\s*banking", r"verify\s*your\s*(account|identity)",
      r"confirm\s*your\s*(account|identity|details)",
      r"raqm\s*el?\s*(kart|card|visa)", r"el?\s*raqm\s*el?\s*siry?", r"el?\s*kart\s*(number|no)"]),
    ("otp_forward", 0.65,
     "الرسالة بتطلب كود التحقق اللي وصلك، وده أخطر أسلوب سرقة حسابات: الكود ده ملكك لوحدك",
     [r"ابعت\s*الكود", r"ارسل\s*الكود", r"اكتب\s*الكود",
      r"الكود\s*اللي\s*(وصلك|جالك|اتبعت)", r"رمز\s*التحقق", r"رمز\s*التفعيل",
      r"\botp\b", r"one.?time\s*(pass)?code", r"send\s*(me\s*)?the\s*code",
      r"share\s*the\s*code", r"verification\s*code", r"كود\s*التحقق", r"(كود|رمز)\s*(ال)?تحقق.{0,40}(ابعت|ابعته|ارسل|اكتب|ابعتهولي|ابعتلي)", r"(ابعت|ابعتهولي|ابعتلي|ارسل|اكتب).{0,20}(كود|رمز)\s*(ال)?(تحقق|التفعيل)",
      r"el?\s*kod\b", r"el?\s*code\s*(elli|el?ly)?", r"kod\s*el?\s*ta.?k?id"]),
    ("prize", 0.5,
     "الرسالة بتقول إنك كسبت جائزة أو هدية من غير ما تشارك في حاجة",
     [r"(ربحت|فزت|مبروك|تهانينا).{0,40}(جائزة|هدية|رصيد|هاتف|ايفون|آيفون|سيارة|مليون)",
      r"(جائزة|هدية)\s*(كبيرة|مجانية|نقدية)", r"قسيمة\s*شراء\s*مجانية", r"يانصيب",
      r"(won|winner|congratulations).{0,50}(prize|gift|iphone|lottery|million)",
      r"free\s*(gift|prize|money)", r"cash\s*prize", r"lottery", r"selected\s*winner",
      r"mabrouk", r"ksebt", r"kisibt", r"gaya?za", r"hedaya|hadiya"]),
    ("urgency", 0.25,
     "الرسالة بتحاول تستعجلك وتخليك تتصرف بسرعة من غير تفكير",
     [r"خلال\s*24", r"خلال\s*48", r"فورا", r"فوراً", r"حالا", r"حالاً",
      r"الان\b", r"الآن\b", r"دلوقتي", r"عاجل", r"اخر\s*فرصة", r"آخر\s*فرصة",
      r"قبل\s*فوات", r"ينتهي\s*(اليوم|العرض)", r"عرض\s*محدود", r"لفترة\s*محدودة",
      r"urgent", r"immediately", r"within\s*24", r"within\s*48",
      r"expires?\s*today", r"last\s*chance", r"act\s*now", r"limited\s*time",
      r"delwa2?ti", r"delwaqti", r"fawran", r"3a2el|3agel"]),
    ("advance_fee", 0.45,
     "الرسالة بتطلب فلوس أو رسوم مقدمة، وده قلب أسلوب النصب بالرسوم",
     [r"(ادفع|ادفعي|سدد|سداد|حوّ?ل\s+(مبلغ|رسوم|الفلوس)|رسوم\s*(الشحن|التخليص|الإفراج|التوصيل|الجمارك)|عربون)",
      r"customs?\s*fee", r"clearance\s*fee", r"delivery\s*fee", r"shipping\s*fee",
      r"processing\s*fee", r"transfer\s*fee", r"small\s*fee", r"redelivery",
      r"مصاريف\s*الشحن", r"ضريبة", r"import\s*duty",
      r"7awwel|7awel|hawwel", r"eflous|folos|felous"]),
    ("crypto_investment", 0.5,
     "الرسالة بتعرض استثمار أو أرباح مضمونة في كريبتو أو تداول، ودي أشهر خدعة استثمار في العالم",
     [r"استثمر", r"منصة\s*استثمار", r"ارباح\s*يومية", r"أرباح\s*يومية", r"عوائد\s*مضمونة",
      r"bitcoin", r"بيتكوين", r"crypto", r"كريبتو", r"\busdt\b", r"tether",
      r"binance", r"باينانس", r"forex", r"فوركس", r"تداول",
      r"guaranteed\s*(returns|profit)", r"double\s*your\s*money",
      r"investment\s*opportunity", r"daily\s*profit", r"trading\s*platform"]),
    ("job_scam", 0.5,
     "عرض شغل سهل بفلوس كتير من غير مقابلة ولا خبرة، وده أسلوب نصب وظائف منتشر",
     [r"وظيفة.{0,30}(راتب|دخل|بيت)", r"شغل\s*من\s*البيت", r"راتب\s*يومي",
      r"بدون\s*خبرة", r"مهام\s*بسيطة", r"عمولة\s*يومية",
      r"work\s*from\s*home", r"no\s*experience\s*(needed|required)",
      r"daily\s*(income|payment)", r"easy\s*money", r"hiring\s*immediately",
      r"part.?time\s*job", r"like\s*and\s*(subscribe|earn)", r"earn\s*\$\d+.*(day|daily)",
      r"(اكسب|اربح)\s*(من|حوالي|ل|لـ)?\s*\d+",
      r"\d+\s*(ل|-|لـ|الى|إلى)\s*\d+\s*(جنيه|دولار|egp|\$)",
      r"(جنيه|دولار|egp|\$).{0,25}(يوميا|يوميًا|في\s*اليوم|يومي)",
      r"(يوميا|يوميًا|في\s*اليوم).{0,25}(جنيه|دولار|egp|\$|\d+)",
      r"الدفع\s*(في\s*)?نفس\s*اليوم", r"الدفع\s*(يومي|فوري)", r"دفع\s*فوري",
      r"same.?day\s*pay", r"paid\s*(daily|same\s*day)", r"instant\s*(payment|payout)",
      r"(شغل|عمل|وظيفة).{0,30}من\s*(البيت|المنزل|الموبايل|موبايلك|التليفون)",
      r"مطلوب\s*\d+\s*(موظف|موظفين|شخص|أفراد|افراد|فرد)",
      r"(مدير|مسؤول|قسم)\s*التوظيف", r"hiring\s*manager", r"recruit(er|ing)\b",
      r"(amazon|أمازون|امازون|جوميا|jumia|نون|noon|شي\s*ان|shein).{0,60}(توظيف|وظيفة|وظائف|موظف|عمل|شغل)",
      r"(توظيف|وظائف).{0,60}(amazon|أمازون|امازون|جوميا|jumia|نون|noon|شي\s*ان|shein)",
      r"الطلبة\s*(غير|مش|لا|ممنوع)", r"شرط\s*السن", r"students?\s*(not\s*allowed|can't|cannot)",
      r"shoghl?\s*m(e|e)n\s*el?\s*b(e|ai)t", r"eks(e|i)b\s*\d+", r"flous\s*yawmiy"]),
    ("telegram_move", 0.4,
     "الرسالة بتنقلك لتليجرام أو محادثة خارجية، ودي حركة النصابين الأساسية عشان يبعدوا عن أي منصة فيها حماية أو إبلاغ",
     [r"تليجرام", r"تيليجرام", r"تلغرام", r"تلجرام", r"telegram", r"تلي\s*جرام",
      r"t\.me/", r"قناة\s*التلي", r"جروب\s*التلي"]),
    ("courier_parcel", 0.5,
     "رسايل الشحن الوهمية بتقول إن في طرد محتجز أو العنوان ناقص وبتطلب رسوم أو بيانات",
     [r"طردك?\s*(محتجز|متوقف|عالق|مرفوض)", r"شحنتك?\s*(محتجزة|متوقفة|عالقة)",
      r"تعذر\s*توصيل", r"فشل\s*(في\s*)?توصيل", r"محاولة\s*توصيل\s*فاشلة",
      r"العنوان\s*(غير\s*(واضح|مكتمل|صحيح)|ناقص)", r"رسوم\s*جمركية", r"جمارك\s*الشحنة",
      r"package\s*(held|pending|stuck|seized)", r"parcel\s*(held|pending|stuck)",
      r"delivery\s*(failed|attempt\s*failed)", r"redelivery\s*fee",
      r"customs?\s*(hold|clearance|fee)", r"address\s*(incomplete|missing|incorrect)",
      r"مكتب\s*البريد.{0,30}(رسم|رسوم|دفع)", r"شركة\s*الشحن.{0,30}(رسم|رسوم|دفع)"]),
    ("wallet_reversal", 0.55,
     "خدعة 'حولتلك بالغلط': بيبعت إيصال تحويل مزور ويطلب الفلوس ترجع، ومفيش تحويل أصلا",
     [r"حولت(lك|لك)?\s*(بالغلط|غلط|بالخطأ)", r"اتحولت\s*(بالغلط|بالخطأ)",
      r"ارجعلي\s*الفلوس", r"التحويل\s*اتعمل\s*(بالخطأ|غلط)", r"رجع\s*(لي|لى)\s*المبلغ",
      r"sent\s*you.{0,25}by\s*mistake", r"wrong\s*transfer", r"refund\s*the\s*transfer",
      r"اكد\s*المحفظة", r"تفعيل\s*المحفظة", r"محفظتك?\s*(اتوقفت|متوقفة|محتاجة\s*تفعيل)",
      r"wallet\s*(suspended|blocked|verify)"]),
    ("romance_inheritance", 0.5,
     "قصص الحب أو الميراث المفاجئة من شخص مجهول بتنتهي بطلب فلوس، ودي من أقدم خدع الإنترنت",
     [r"ميراث", r"ورثت", r"تركة", r"محامي.{0,30}(متوفي|ميراث|تركة)", r"أرملة|ارملة",
      r"next\s*of\s*kin", r"inheritance", r"unclaimed\s*(fund|money|deposit)",
      r"deceased\s*(client|relative)", r"\bwidow\b",
      r"(حبيبي|حبيبتي).{0,50}(فلوس|مبلغ|حوالة|كارت|بطاقة)",
      r"(soldier|army|military).{0,60}(send|transfer|money|package|customs)",
      r"(un\s*|united\s*nations\s*)(soldier|doctor|peacekeeping)"]),
    ("sextortion", 0.6,
     "ابتزاز بصور أو فيديوهات خاصة وطلب فلوس مقابل عدم النشر: بلاغ فوري ومتدفعش",
     [r"فيديو.{0,25}(خاص|محرج|فاضح|ابتزاز)", r"صور(ك|كي)?\s*(الخاصة|المحرجة|الفاضحة)",
      r"فضحك|افضحك|هفضحك|فضيحة", r"هدمر\s*سمعتك",
      r"recorded\s*(you|your|u)", r"webcam\s*(video|recording)",
      r"embarrassing\s*(video|photos|pics)", r"expose\s*(you|your)",
      r"publish\s*your\s*(video|photos|pics)",
      r"(video|photos).{0,60}(bitcoin|btc\s*wallet)"]),
    ("loan_scam", 0.45,
     "قروض فورية بدون ضمانات من رسايل مجهولة: شركات التمويل الحقيقية مش بتعرض قروض برسايل",
     [r"قرض\s*(فوري|سريع|بسيط|مضمون)", r"تمويل\s*(شخصي\s*)?(فوري|سريع)",
      r"قروض\s*بدون", r"بدون\s*ضمانات", r"قرضك\s*(جاهز|اتوافق)",
      r"loan\s*(offer|approved|within)", r"quick\s*(loan|cash)", r"no\s*collateral",
      r"get\s*a\s*loan\s*(now|today|fast)", r"تمويل\s*مشروعك.{0,30}(فوري|بدون)"]),
    ("rental_scam", 0.45,
     "طلب عربون أو حجز قبل معاينة الشقة علامة نصب إيجار معروفة",
     [r"عربون.{0,30}(شقة|الشقة|معاينة|حجز)", r"حجز\s*الشقة", r"ادفع\s*عربون",
      r"(شقة|سكن|أوضة|اوضة).{0,40}(عربون|حجز\s*قبل)",
      r"deposit\s*(before|to)\s*(viewing|view|rent)", r"rent\s*deposit\s*(now|first)",
      r"keys?\s*(will\s*be\s*)?sent"]),
    ("marketplace_scam", 0.5,
     "خدع البيع والشراء: مندوب وهمي أو طلب تحويل فلوس قبل الاستلام",
     [r"هبعت\s*(لك\s*)?(المندوب|مندوب)", r"المندوب\s*(هيدفع|هيديك|في\s*الطريق)",
      r"حو?ل\s*(الفلوس|المبلغ|الثمن).{0,25}(فودافون\s*كاش|كاش|انستاباي|محفظة)",
      r"(الاول|الأول).{0,15}(حوالة|تحويل|كاش|الدفع)", r"(فودافون\s*كاش|انستاباي|كاش|المحفظة)\s*(الاول|الأول|قبل)",
      r"\bolx\b", r"اولكس", r"دوبيزل", r"سوق\s*المفتوح", r"opensooq",
      r"send\s*(a\s*|my\s*)?courier", r"courier\s*will\s*(pay|collect)"]),
    ("charity_scam", 0.35,
     "مناشدات تبرع عاطفية برسايل مجهولة: تأكد من الجمعية الرسمية قبل أي تبرع",
     [r"حالة\s*إنسانية", r"تبرع\s*(عاجل|فوري)", r"عملية\s*(جراحية|قلب|زرع).{0,30}(تبرع|مبلغ|فلوس)",
      r"ساهم\s*(معانا|معنا).{0,25}(تبرع|مبلغ)", r"donate\s*(now|urgently)",
      r"urgent\s*donation", r"relief\s*fund", r"sick\s*(child|baby).{0,40}donat"]),
    ("qr_scam", 0.45,
     "مسح رمز QR من رسالة مجهولة ممكن يسرق حسابك أو يسبّت برنامج خبيث",
     [r"امسح\s*(الكود|الرمز|الباركود|qr)", r"scan\s*(the\s*)?qr",
      r"رمز\s*الاستجابة\s*السريعة", r"كود\s*الاستجابة", r"qr\s*code\s*(scan|to\s*(pay|receive|verify))"]),
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

"""Build data/combined.csv from the raw datasets in data/.

Sources (see RESEARCH.md for why each one):
  - SMSSpamCollection    : UCI English SMS spam (real SMS, 2011)
  - Arabic_Spam_raw.csv  : Arabic SMS spam, Saudi bank phishing (real)
  - arabic_messages.csv  : 50 Arabic examples from the arabpython project
  - imc25_smishing.csv   : 33k real reported smishing messages in 7 languages,
                           from the IMC 2025 paper "Fishing for Smishing"
  - moz_smishing.csv     : Mozambique SMS, Portuguese, legit + smishing
  - smishing_combined.csv: English smishing/spam labels (sampled)
  - egyptian examples    : hand-written Egyptian colloquial, source=eg_synthetic

Output columns: text,label,source   label: 1 scam/spam, 0 legitimate
The scam class is capped near 2.5x the legit class so the model does not
learn to call everything a scam.
"""

import csv
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")

# Written from the documented public patterns in data/EGYPT_PATTERNS.md.
# Still synthetic: modeled on official warnings, not harvested messages.
EG_SCAM_EXTRA = [
    # P1 prize lures
    "مبروك كسبت جائزة 100 ألف جنيه من البنك الأهلي، لتأكيد الاستلام ادخل بياناتك هنا",
    "تهانينا! حضرتك الفائز بجائزة البنك الأسبوعية 25000 جنيه، اضغط على الرابط لاستلامها",
    "مبروك كسبت جائزة من مسابقة البنك، سجل بيانات بطاقتك عشان نحولك المبلغ",
    "فودافون كاش: مبروك ربحت 10 آلاف جنيه، ابعت الرقم السري لتأكيد المحفظة",
    "كسبان معانا 5000 جنيه رصيد، حول 50 جنيه رسوم تفعيل على الرقم ده",
    "مبروك عليك الإيفون، ادفع مصاريف الشحن 200 جنيه فودافون كاش على الرقم ده",
    # P2 wallet impostors
    "أنا من خدمة عملاء فودافون كاش، محفظتك هتتقفل النهارده، اديني الرقم السري أحدثها",
    "عزيزي العميل محفظتك تحتاج تحديث، دخل الرقم السري ورقم البطاقة في اللينك",
    "محفظة انستاباي بتاعتك متوقفة مؤقتا، فعلها من هنا قبل منتصف الليل",
    "تم استلام حوالة ليك بمبلغ 3000 جنيه، ادخل بيانات محفظتك لاستلامها",
    "خدمة عملاء وي كاش: في عملية سحب من محفظتك، ابعت كود التحقق فورا لإلغائها",
    "رصيدك المجاني 1000 جنيه جاهز، أكد رقمك والرقم السري عشان يتضاف",
    # P3 fake purchase + cancel link
    "تم خصم 4,750 جنيه من بطاقتك لعملية شراء. لو مش حضرتك اللي عملتها اضغط لإلغاء العملية",
    "عملية تحويل بمبلغ 12000 جنيه قيد التنفيذ من حسابك، لإيقافها فورا اضغط هنا",
    "تنبيه: تم شراء اشتراك بقيمة 99 دولار من حسابك، ألغي العملية من الرابط خلال ساعة",
    # P4 instapay update
    "انستاباي: لازم تحدث بياناتك قبل 30 يونيه ولا حسابك هيتوقف نهائي",
    "تحديث أمني إجباري لحسابك على انستاباي، أكمل بياناتك من هنا",
    "عطل في خوادم انستاباي، سجل دخولك من اللينك ده عشان متفقدش فلوسك",
    # P5 government/utility/post
    "البريد المصري: شحنتك محتجزة في الجمارك، سدد رسوم الإفراج 65 جنيه من هنا",
    "وزارة التموين: تم اختيارك لدعم استثنائي 2000 جنيه، سجل بيانات بطاقتك التموينية",
    "رسالة من الإسكان الاجتماعي: اخر موعد لحجز شقتك بمقدم 5000 جنيه، ادفع أونلاين دلوقتي",
    "غرامة مرورية مسجلة على رخصتك بقيمة 300 جنيه، ادفع من هنا قبل مضاعفتها",
    "معاش تكافل وكرامة: صرف دفعة استثنائية، اكتب رقمك القومي ورقم المحفظة",
    "كهرباء مصر: فاتورتك متأخرة والعداد هيتفصل خلال 24 ساعة، سدد من الرابط",
    # P6 whatsapp/telegram gift groups
    "انضم لجروب الهدايا الرسمي على تليجرام، أول 100 مشترك ليهم 5000 جنيه",
    "قناة واتساب الرسمية للبنك المركزي بتوزع هدايا، سجل اسمك ورقمك هنا",
    "دخلت جروب ربح الموبايلات، ابعت بياناتك للأدمن عشان تستلم هديتك",
    # P7 jobs / otp / misc
    "مطلوب موظفين داتا إنتري من البيت براتب 15 ألف، رسوم التسجيل 150 جنيه بس",
    "تم قبولك في وظيفة أورانج، ادفع رسوم الكشف الطبي 250 جنيه لاستكمال التعيين",
    "وظيفة لايكات للتيك توك: اكسب 300 جنيه في اليوم، ادفع 100 جنيه تأمين حساب",
    "أنا ابنك، موبايلي اتكسر وده رقمي الجديد، ابعتلي 500 جنيه كاش على الرقم ده ضروري",
    "يا ماما أنا رقمي الجديد، محتاج حوالة 800 جنيه دلوقتي هردهالك بكرة",
    "وصلك كود تأكيد من فودافون بالغلط، ابعتهولي بسرعة عشان خدمة العملاء",
    "بعتلك كود تحقق، ابعتهولي عشان أساعدك تحل مشكلة المحفظة",
    "استثمر 1000 جنيه في منصة التداول وخد 4000 بعد أسبوع، أرباح مضمونة",
    "منصة استثمار مصرية مرخصة، ضاعف فلوسك في 5 أيام، سجل وادفع أول إيداع",
    "فرصة تعدين بيتكوين من التليفون، ابدأ بـ 50 دولار واربح يوميا",
    "عربيتك كسبت في السحب، مطلوب كوبري البطاقة والرقم السري للتأكيد",
    "عندك ميراث في البنك من قريبك المتوفي، ابعت صورة البطاقة للمحامي",
    "حجز شقق الإسكان فتح تاني، احجز دلوقتي بعربون 1000 جنيه على المحفظة",
    "نداء أخير: حسابك البنكي هيتجمد بسبب عدم تحديث البيانات، حدث من هنا",
    "فيزا مجانية للسعودية بدون شروط، ابعت صورة البطاقة ورسوم 400 جنيه",
    "قرض فوري بدون ضمانات ببطاقتك بس، سجل بياناتك في الفورم",
    "اعمل خير وكسب، تبرعك هيتضاعف 10 مرات في حملة رمضان، حول هنا",
    "تم إيقاف خطك بسبب عدم تحديث البيانات، كلم 555 أو حدث من اللينك",
    "عرض WE: باقة سنة كاملة بنص التمن، الحق العرض قبل ما يخلص النهارده",
    "اتصالات بتوزع 100 جيجا مجانا، اضغط هنا وفعل العرض قبل نص الليل",
    "أورانج: كسبت 50 جيجا هدية، شارك الرسالة دي مع 10 أصحابك عشان تستلم",
]

EG_LEGIT_EXTRA = [
    "تنبيه: تم صرف معاش شهر نوفمبر، يمكنك الاستعلام من أقرب ماكينة ATM",
    "فودافون: تم استلام مدفوعاتك بنجاح، شكرا لسدادك الفاتورة",
    "تم إضافة 25 جيجا لباقتك بعد التجديد، صالحة لمدة 28 يوم",
    "بنك مصر: تم تنفيذ التحويل اللي طلبته بنجاح، إيصال العملية في التطبيق",
    "انستاباي: وصلك تحويل بمبلغ 1500 جنيه من أحمد محمد، رصيدك اتتحدث",
    "عزيزي العميل، موعد صرف تكافل وكرامة يوم 15 من ماكينات فوري",
    "طلبك من جوميا اتشحن، الكابتن هيكلمك قبل التوصيل",
    "شحنة أرامكس وصلت نقطة الاستلام، كود الاستلام 4521",
    "ميعادك في العيادة بكرة الساعة 7 مساء، لو هتأجل كلمنا",
    "مدرسة المستقبل: غدا يوم دراسي عادي، الامتحان اتأجل للأسبوع الجاي",
    "فاتورة النت المنزلي 330 جنيه، السداد قبل يوم 10 عشان الخدمة متفصلش",
    "تم تجديد اشتراكك في صالة الجيم لمدة شهر، بالهنا",
    "عام دراسي سعيد! أول يوم مذاكرة السبت الجاي الساعة 4",
    "حضرتك حجزت تذكرتين سينما يوم الجمعة 9 مساء، الكود في الإيميل",
    "الغسالة اتصلحت وتقدر تستلمها من المركز أي وقت من 10 لـ 6",
    "يا بابا وصلت الجامعة، هكلمك لما أخلص",
    "التوصيل في الطريق، الأوردر هيوصلك خلال 20 دقيقة",
    "تم شحن رصيد 30 جنيه لخطك بنجاح",
    "نذكرك بميعاد تحليلك بكرة صائم من 9 الصبح في معمل البرج",
    "قسط العربية اتخصم بنجاح، القسط الجاي يوم 1 الشهر الجاي",
]

EG_SCAM = [
    "عميلنا العزيز تم إيقاف حسابك البنكي، لتنشيط الحساب اضغط على اللينك فورا",
    "مبروك كسبت 50 ألف جنيه من فودافون كاش، ابعت رقمك وكود التفعيل",
    "حضرتك عندك طرود متوقفة في الجمارك، ادفع رسوم التخليص 150 جنيه على اللينك",
    "تم حظر حسابك في انستاباي نهائي، أكد بياناتك خلال 24 ساعة ولا الحساب هيتقفل",
    "عايز تكسب من غير شغل؟ استثمر 500 جنيه وخد 5000 في أسبوع، كلمنا واتساب",
    "فزت بايفون 15 برو من مسابقة أورانج، ادفع مصاريف الشحن بس",
    "رسالة أمنية: تم رصد محاولة دخول على حسابك، غير كلمة السر من اللينك دلوقتي",
    "بنك مصر: تم تعليق بطاقتك الائتمانية، اتصل بالرقم ده وابعت رقم الكارت والرقم السري",
    "عرض محدود: شقة بالتقسيط بدون مقدم في العاصمة الإدارية، احجز بعربون 2000 جنيه",
    "حسابك على واتساب هيتقفل النهارده، ابعت الكود اللي جالك عشان نثبت ملكيتك",
    "تم اختيارك للعمل من البيت براتب 20 ألف جنيه، سجل بياناتك في الفورم",
    "لديك حوالة مالية لم تستلمها، اضغط هنا وأدخل بيانات البطاقة لاستلامها",
    "شركة الشحن: طردك محتجز، سدد 99 جنيه رسوم إفراج خلال 3 ساعات وإلا هيرجع",
    "أخيرا التوصيل مجاني، اطلب الآن من اللينك ده قبل نهاية العرض النهارده",
    "فوري: تم خصم مبلغ بالغلط من محفظتك، لاسترداده ابعت رقم المحفظة والرقم السري",
    "مبروك فزت بمليون جنيه في برنامج المسابقة، اتصل دلوقتي وابعت رقم بطاقتك",
    "تم رصد عملية شراء مشبوهة على حسابك، لو مش انت اضغط هنا وأدخل بياناتك",
    "وظيفة مندوب مبيعات براتب ثابت وعمولة، المقابلة أونلاين برسوم تسجيل 200 جنيه",
    "البريد المصري: شحنتك وصلت، ادفع الضريبة 45 جنيه من اللينك عشان تتسلمها",
    "تهانينا! رقمك فاز بقسيمة شراء 1000 جنيه من أمازون، فعلها خلال ساعة",
]

EG_LEGIT = [
    "صباح الخير يا باشا، الشحنة هتوصلك بكرة إن شاء الله",
    "فودافون: تم تجديد باقتك بنجاح، رصيدك الحالي 12.5 جنيه",
    "ياريت تبعتلي التقرير لما تخلصه عشان الاجتماع بكرة",
    "تم استلام طلبك رقم 4521، وهيوصلك خلال 3 أيام عمل",
    "الدكتور قال الميعاد اتأجل ليوم الخميس الساعة 5",
    "محفظتك اتشحنت بمبلغ 200 جنيه بنجاح، رصيدك دلوقتي 230 جنيه",
    "يا رياض فينك، الماتش بدأ خلاص",
    "تم تسجيل حضورك اليوم الساعة 9:05 صباحا",
    "الأوردر بتاعك اتجهز، تقدر تستلمه من الفرع أي وقت",
    "أذان المغرب حان الآن حسب التوقيت المحلي",
    "كشف حسابك الشهري متاح دلوقتي على التطبيق",
    "ماما بتقولك تعالى الغدا لما تخلص",
    "تم تأكيد حجزك في مطعم النيل يوم الجمعة الساعة 8 مساء",
    "عام سعيد! كل سنة وانت طيب يا صاحبي",
    "محاضرة النهارده اتلغت، الدكتور مريض",
    "رصيدك أوشك على الانتهاء، اشحن عشان الخط ميفصلش",
    "فاتورة الكهرباء الشهر ده 340 جنيه، آخر ميعاد للسداد يوم 15",
    "تم تسليم الشحنة بنجاح، شكرا لتعاملكم معنا",
    "يا جماعة الاجتماع اتنقل ليوم الحد بدل التلات",
    "قسط الجامعة لازم يتدفع قبل آخر الشهر عشان ميتحسبش غرامة",
    "تم تجديد باقتك بنجاح. لمتابعة استهلاكك زوروا https://www.vodafone.com.eg",
    "اتصالات: عرضك الجديد متاح على التطبيق https://www.etisalat.eg",
    "لمتابعة فاتورتك زوروا موقعنا https://www.orange.eg",
    "كشف الحساب الشهري متاح على https://www.banquemisr.com",
    "تم إضافة المستفيد بنجاح. لإدارة حسابك زوروا https://www.cibeg.com",
    "تنبيه: تم تسجيل دخول لحسابك من جهاز جديد. لو حضرتك مش اللي عملت كده اتصل بخدمة العملاء على الرقم المكتوب ورا البطاقة",
    "رقم تتبع شحنتك متاح على https://www.egyptpost.gov.eg",
    "تم شحن محفظتك من فوري، تقدر تراجع العملية على https://www.fawry.com",
    "للاستعلام عن رصيدك كلم 555 أو زوروا https://www.te.eg",
    "حجزك اتأكد على https://www.booking.com وتفاصيل الرحلة في الإيميل",
    "طلبك من أمازون في الطريق، تابعه من https://www.amazon.eg",
]


def read_uci(path):
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            label, _, text = line.partition("\t")
            rows.append((text.strip(), 1 if label == "spam" else 0, "uci_en"))
    return rows


def read_arabic_spam(path):
    rows = []
    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            text = (r.get("SMS") or "").strip()
            if text:
                rows.append((text, 1 if (r.get("Sentiment") or "0").strip() == "1" else 0, "ar_saudi"))
    return rows


def read_arabpython(path):
    rows = []
    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            text = (r.get("message") or "").strip()
            if text:
                rows.append((text, 1 if (r.get("label") or "").strip() == "spam" else 0, "ar_misc"))
    return rows


def read_imc25(path, cap):
    rows = []
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for r in csv.DictReader(f):
            if (r.get("scam_type") or "").strip() in ("", "spam"):
                continue
            text = (r.get("text") or "").strip()
            if 15 <= len(text) <= 600:
                rows.append((text, 1, "imc25_" + (r.get("language") or "?").lower()))
    random.Random(7).shuffle(rows)
    return rows[:cap]


def read_moz(path):
    rows = []
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for r in csv.DictReader(f):
            text = (r.get("text") or "").strip()
            label = (r.get("label") or "").strip()
            if text and label in ("Smishing", "Legitimate"):
                rows.append((text, 1 if label == "Smishing" else 0, "moz_pt"))
    return rows


def read_shaghayegh(path, cap):
    rows = []
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for r in csv.DictReader(f):
            if (r.get("smishing label") or "").strip() != "1":
                continue
            text = (r.get("message") or "").strip()
            if 15 <= len(text) <= 600:
                rows.append((text, 1, "smishing_en"))
    random.Random(11).shuffle(rows)
    return rows[:cap]


# ---------- V2: broad scam-format coverage (jobs, courier, wallets, romance,
# sextortion, loans, rentals, marketplace, charity, QR, Franco-Arabic) ----------
# Same rule as above: modeled on documented public patterns, marked eg_synthetic.

def _v2_job_scams():
    out = []
    brands = ["أمازون", "جوميا", "نون", "شي ان", "Amazon", "Noon", "Shein", "Jumia"]
    pays = ["1000 ل 3000", "500 ل 1500", "2000 ل 5000", "800 ل 2500", "1500 ل 4000", "750 ل 2000"]
    handles = ["vip347", "hr_amazon_eg", "jobs2026", "work_now9", "amz_recruit", "task_eg88"]
    conds = ["السن +20 والطلبة غير متاحين", "السن من 21 ل 45", "متاح للجميع بدون خبرة",
             "شرط السن +18", "بدون شهادة ولا خبرة", ""]
    intros = ["مدير التوظيف:", "قسم الموارد البشرية:", "إدارة التوظيف:", "مسؤول التوظيف:", ""]
    for b in brands:
        for p in pays:
            h = random.Random(hash((b, p)) % 10**6).choice(handles)
            c = conds[(hash(b) + hash(p)) % len(conds)]
            i = intros[(hash(b + p)) % len(intros)]
            t = (f"شركة {b} {i} مطلوب موظفين للعمل اونلاين جزئي من الموبايل. "
                 f"اكسب من {p} جنيه يوميا وانت في البيت، الدفع في نفس اليوم. "
                 f"للتواصل عبر تليجرام @{h} او t.me/{h}")
            if c:
                t += f" - ملحوظة: {c}"
            out.append(t)
    out += [
        "وظيفة اونلاين: اعمل لايكات لفيديوهات واكسب عمولة يومية 200 جنيه، للتسجيل كلمنا تليجرام",
        "مهام بسيطة من موبايلك: لايك واشتراك واكسب فلوس يوميا، الدفع عبر تليجرام بعد كل مهمة",
        "مطلوب 50 شخص يقيموا منتجات على النت، عمولة يومية مضمونة، تواصل تليجرام للبدء فورا",
        "Amazon hiring 80 remote part-time workers, earn 1000-3000 EGP daily from your phone, paid same day. Contact Telegram @vip347 (must be 20+, no students)",
        "We are hiring! Work from home, no experience needed, daily income $50-$150, paid instantly. Message us on Telegram to start today",
        "شغل من البيت براتب يومي 700 جنيه، بدون خبرة، ابعت كلمة 'تم' على التليجرام وهنشرحلك",
        "تليجرام للشغل: قناة فيها شغل يومي بفلوس كاش كل يوم، ادخل الجروب وابدا اكسب",
    ]
    return out


def _v2_courier():
    return [
        "شركة الشحن: طردك محتجز في الجمارك، ادفع رسوم جمركية 120 جنيه عبر الرابط لتسليمه",
        "تعذر توصيل شحنتك لأن العنوان غير مكتمل، حدث بياناتك خلال 24 ساعة وإلا سيتم إرجاعها",
        "DHL: your package is held at customs, pay the clearance fee here to release it",
        "فشل توصيل الطرد، محاولة توصيل فاشلة. ادفع رسوم إعادة التوصيل من الرابط",
        "بريد مصر: شحنتك متوقفة لحين سداد رسوم التخليص الجمركي، اضغط للدفع",
        "Your parcel delivery failed due to an incomplete address. Pay the redelivery fee to reschedule",
        "أرامكس: في رسوم جمركية على شحنتك 85 جنيه، سددها اونلاين عشان تتسلم",
        "مكتب البريد: عندك طرد عالق، ادفع رسم التخزين 40 جنيه قبل إرجاعه للمرسل",
    ]


def _v2_wallet():
    return [
        "حولتلك 3000 جنيه بالغلط على محفظتك، لو سمحت ارجعلي الفلوس على الرقم ده",
        "يا أخي التحويل اتعمل بالخطأ، رجعلي المبلغ فودافون كاش وأنا تحت أمرك",
        "محفظتك اتوقفت لأسباب أمنية، فعل المحفظة من الرابط ده عشان تقدر تستلم فلوس",
        "فودافون كاش: محتاجين تأكيد محفظتك، اكتب الرقم السري هنا للتحقق",
        "I sent you money by mistake, please refund the transfer to this wallet",
        "انستاباي: في حوالة واردة مستنية تفعيل حسابك، ادخل بيانات بطاقتك للاستلام",
        "وصلك مبلغ معلق! اكد محفظتك دلوقتي بإدخال الرقم السري وإلا هيرجع للمرسل",
        "تم إيقاف محفظة الموبايل مؤقتا، لتفعيل المحفظة اضغط على الرابط وسجل الدخول",
    ]


def _v2_romance_inherit():
    return [
        "أنا أرملة من سوريا وورثت 3 مليون دولار، محتاجة شريك يستلم المبلغ وهتاخد 40%",
        "محامي في لندن: موكلي المتوفي له تركة 2.5 مليون يورو وأنت next of kin، رد للتفاصيل",
        "My late client left an unclaimed deposit of $4.7M. I want to present you as next of kin. Reply for details",
        "حبيبتي انا العسكري جون من القوات الأمريكية، عايز أبعتلك صندوق فيه فلوس، ادفعي بس رسوم الجمارك",
        "I am a UN peacekeeping doctor in Yemen, I want to send you a package with my savings, pay the customs fee for me my love",
        "خطيبك من الخليج: حبيبي ابعتيلي كروت شحن عشان أكلمك، رصيدي خلص",
        "Dear beloved, I am a widow with an inheritance of millions, help me transfer it and you will get half",
        "شخص مجهول عايز يحولك ميراث عمك اللي مات في الخارج، ابعت بياناتك البنكية كاملة",
    ]


def _v2_sextortion():
    return [
        "سجلنا فيديو خاص ليك من الكاميرا، ادفع 500 دولار بيتكوين وإلا هننشره لكل أصحابك",
        "عندنا صورك المحرجة، حول المبلغ على المحفظة دي وإلا هنفضحك قدام عيلتك",
        "We recorded you through your webcam. Pay in bitcoin or we publish your video to all contacts",
        "I have your embarrassing video. Send BTC to this wallet within 24 hours or everyone sees it",
        "هفضحك بالفيديو اللي معايا لو مبعتتش 5000 جنيه فودافون كاش قبل بكرة",
        "جهازك اتخترق وكل صورك الخاصة عندنا، الدفع بيتكوين وإلا الفضيحة",
    ]


def _v2_loan():
    return [
        "قرض فوري بدون ضمانات وبدون مقدم، من 5000 ل 500 ألف جنيه، التمويل في 24 ساعة، كلمنا واتساب",
        "قروض بدون ضمانات للموظفين والطلبة، تمويل شخصي سريع بإجراءات بسيطة، ابعت بياناتك",
        "Get a loan today, approved within hours, no collateral needed. Quick cash, message us now",
        "قرضك جاهز! تمت الموافقة المبدئية على تمويل 100 ألف، ادفع رسوم التفعيل للاستلام",
        "تمويل مشروعك فوري وبدون فوائد، ابعت صورة البطاقة ومحل السكن للبدء",
        "Quick loan offer: $1000-$50000 approved today, no credit check, small processing fee first",
    ]


def _v2_rental():
    return [
        "الشقة لسه متاحة، ادفع عربون 1000 جنيه فودافون كاش عشان أحجزلك الشقة قبل حد ياخدها",
        "معاينة الشقة بكرة، بس لازم عربون الحجز الأول عشان الناس بتهزر كتير",
        "Apartment available, pay the deposit before viewing and the keys will be sent to you",
        "سكن طلبة: اوضة قريبة من الجامعة، احجز بعربون 500 جنيه والشقة مضمونة",
        "للإيجار شقة مفروشة بسعر حلو، بس صاحبها في الخارج: ابعت العربون والمفاتيح هتوصلك بالبريد",
    ]


def _v2_marketplace():
    return [
        "هبعتلك المندوب يستلم التليفون وهو هيديك الفلوس، بس حولي 200 جنيه تأمين المندوب الأول",
        "تمام يا باشا، المندوب في الطريق، ابعت رقمك السري عشان يقدر يحولك الفلوس على المحفظة",
        "عايز المنتج، هبعت شركة شحن تدفعلك وتستلم، بس سجل في الرابط ده الأول",
        "حول الثمن على فودافون كاش الأول وأنا أبعتلك المنتج بالبريد، متقلقش أنا موثوق",
        "OLX buyer: I will send a courier with the cash, just pay the courier insurance fee first",
        "الدفع كاش عند الاستلام، بس اطلب منك تحويل رمز التحقق اللي هيوصلك عشان أتأكد إنك جاد",
    ]


def _v2_charity_qr():
    return [
        "حالة إنسانية عاجلة: طفلة محتاجة عملية قلب بكرة، تبرع فوري على رقم المحفظة ده",
        "ساهم معانا في علاج مريض، أي مبلغ يفرق، التبرع فودافون كاش على الرقم",
        "Urgent donation needed for a sick child, donate now to this wallet, every dollar counts",
        "امسح كود الـ QR ده عشان تستلم رصيدك المجاني من العرض",
        "Scan the QR code to verify your wallet and receive your reward",
        "رمز الاستجابة السريعة ده هيدخلك السحب على المليون، امسحه من الكاميرا",
        "تبرعك العاجل مطلوب لضحايا الحريق، حول أي مبلغ على المحفظة دي جزاك الله خيرا",
    ]


def _v2_franco():
    return [
        "mabrouk ksebt gaya?za 10000 gneh, eb3at raqm el kart wel raqm el sery 3ashan testalemha",
        "7esabak et2af, lazem ted5ol 3ala el link da w te2added el 7esab delwa2ti",
        "7awwel 50 gneh 3ala el raqm da 3ashan te3addel el gawaz wel flous hatewasalak fawran",
        "el kod elli haywessalak eb3atoholy, da kod el ta2kid beta3 el transfer",
        "shoghl men el bet, ekseb 1000 gneh yawmian, kallemny telegram",
        "eflous kteer men gher sho3'l, bas lazem tedfa3 رسوم صغيرة الأول",
        "ana mama, raqmy el gedid da, telephone etkasser, eb3atily kart shahn 100 gneh 3ashan akallemk",
        "your account is suspended, verify now: raqm el kart wel cvv",
    ]


def _v2_english_global():
    return [
        "USPS: your package cannot be delivered due to incomplete address, update here within 12h",
        "Bank of America alert: unusual activity detected, verify your identity immediately",
        "Your Apple ID has been locked. Confirm your account details to unlock",
        "Netflix: your payment failed, update your billing information to keep your membership",
        "IRS: you have a tax refund pending, submit your details to claim it",
        "Your McAfee subscription expired, call this number immediately to avoid charges",
        "Congratulations! You've been selected as the winner of our $1,000 Walmart gift card",
        "COINBASE: A withdrawal of 0.45 BTC was requested. If not you, call support immediately",
    ]


EG_SCAM_V2 = (_v2_job_scams() + _v2_courier() + _v2_wallet() + _v2_romance_inherit()
              + _v2_sextortion() + _v2_loan() + _v2_rental() + _v2_marketplace()
              + _v2_charity_qr() + _v2_franco() + _v2_english_global())

EG_LEGIT_V2 = [
    # real telecom / wallet / transfer traffic (must NOT be flagged)
    "فودافون: تم تجديد باقتك الشهرية بنجاح، رصيدك الحالي 12.5 جنيه",
    "تم تحويل 200 جنيه من محفظة محمد أ. إلى محفظتك، الرصيد الحالي 430 جنيه",
    "انستاباي: استلمت 1500 جنيه من شركة النور للتجارة",
    "رسالة من البنك الأهلي: تم خصم 350 جنيه من بطاقتك لدى كارفور المعادي",
    "كود التحقق الخاص بك هو 482910، لا تشاركه مع أي شخص",
    "أورانج: عرض خاص ليك، ضعف الباقة لمدة شهر عند التجديد من تطبيق أورانج",
    "WE: تم سداد فاتورة الإنترنت الأرضي بنجاح، شكرا لتعاملكم معنا",
    # real delivery
    "شحنتك من جوميا هتوصلك بكرة بين 10 صباحا و 6 مساء، تتبعها من التطبيق",
    "أرامكس: تم تسليم شحنتك بنجاح، شكرا لتسوقكم معنا",
    "طلبك من أمازون.إيجيبت في الطريق إليك، المندوب هيكلمك قبل الوصول",
    # real job ads (monthly salary, formal channel)
    "مطلوب محاسب خبرة 3 سنوات للعمل بشركة بالتجمع الخامس، راتب 8000 جنيه شهريا، التقديم على الإيميل jobs@company.com",
    "وظيفة مطور تطبيقات بشركة برمجيات بالمهندسين، راتب مجزي حسب الخبرة، قدم عبر لينكد إن",
    "شركة أدوية تطلب مندوبين مبيعات، مقابلة يوم الثلاثاء في المقر الرئيسي بالمعادي",
    "Vacancy: accountant needed, 3+ years experience, monthly salary, apply via LinkedIn with your CV",
    # family / personal
    "يا رياد وصلت البيت، كلمني لما تفضى",
    "بابا: فلوس الكهرباء معاك ولا أشحن العداد أنا؟",
    "هي يا ستي الوحشة، بعتلك صور العيلة على واتساب",
    "ماما: موبايلي شحنه خلص هكلمك من تليفون البيت",
    # marketplace legit
    "التليفون لسه موجود، تيجي تشوفه النهاردة الساعة 7 في مدينة نصر؟",
    "أنا وصلت تحت العمارة، انزل استلم المنتج وادفع كاش",
    "معذرة السعر نهائي، لو مناسبك نتقابل بكرة في محطة المترو",
    # work
    "اجتماع الفريق اتنقل لبكرة الساعة 11 على زوم",
    "أستاذ رياد، التقرير المطلوب هيكون جاهز آخر الأسبوع إن شاء الله",
    # gov real
    "وزارة الصحة: موعد تطعيمك يوم الخميس في وحدة صحة الحي الرابع",
    "تم تجديد رخصة القيادة بنجاح عبر بوابة مصر الرقمية، يمكنك استلامها من وحدة المرور",
]


# ---------- V2 legit lookalikes: close collisions with scam wording ----------
def _v2_legit_lookalikes():
    out = []
    amounts = ["200", "400", "750", "1200", "1500", "3000", "500", "950"]
    senders = ["محمد أ.", "شركة النور", "أحمد س.", "حساب شركتنا", "منى ع.", "والدك"]
    wallets = ["فودافون كاش", "انستاباي", "اتصالات كاش", "اورانج موني"]
    i = 0
    for w in wallets:
        for a in amounts:
            s = senders[i % len(senders)]
            bal = int(a) + 137
            out.append(f"{w}: استلمت {a} جنيه من {s}، رصيدك الحالي {bal} جنيه")
            out.append(f"وصلك تحويل {a} جنيه من {s} عبر {w}")
            i += 1
    out += [
        "CIB: تم إضافة مبلغ 9500 جنيه إلى حسابك، الرصيد المتاح 22,310 جنيه",
        "بنك مصر: تم خصم 780 جنيه من بطاقتك لدى متجر سبينيس، رصيدك المتاح 14,020 جنيه",
        "البنك الأهلي: تم استلام حوالة خارجية بقيمة 500 دولار وإضافتها لحسابك",
        "QNB: تم تنفيذ التحويل بنجاح، الرصيد الحالي 9,800 جنيه",
        "كود التحقق الخاص بك هو 482910، صالح لمدة 5 دقائق، لا تشاركه مع أي شخص",
        "رمز الدخول: 551208، إذا لم تقم بهذه العملية اتصل بالبنك فورا",
        "Your verification code is 664291. Never share it with anyone.",
        "رمز تأكيد العملية: 093214، فريق البنك لن يطلبه منك أبدا",
        "مطلوب سكرتيرة للعمل بمكتب محاماة، الدوام 9 ل 5، الراتب 6000 جنيه شهري، المقابلة بالمكتب",
        "وظيفة خدمة عملاء بشركة اتصالات، راتب ثابت 7500 جنيه شهريا + حوافز، التقديم من موقع الشركة",
        "مطلوب مهندس مدني خبرة 5 سنوات لموقع بالعاصمة الإدارية، المرتب حسب الخبرة، ارسل سيرتك على الإيميل",
        "شركة مقاولات تطلب محاسبين، مقابلات يوم الخميس في المقر، يفضل قرب السكن من مدينة نصر",
        "We are hiring a sales rep in Cairo, 2 years experience, monthly pay, apply with your CV on LinkedIn",
        "Hiring: backend engineer, remote within Egypt, monthly salary, apply through our careers page",
        "Vacancy: pharmacist needed in Tanta, full-time, apply at the branch with your documents",
        "بوابة مصر الرقمية: تم استلام طلبك لتجديد بطاقة الرقم القومي وسيتم التوصيل خلال 7 أيام عمل",
        "وزارة الداخلية: تم تجديد رخصة سيارتك بنجاح، يمكنك استلامها من وحدة المرور",
        "الشهر العقاري: موعدك لتوقيع العقد يوم الثلاثاء الساعة 11 صباحا في المكتب الرئيسي",
        "شحنتك من نون هتوصلك النهاردة، المندوب هيكلمك قبل الوصول",
        "جوميا: طلبك اتسلم للمندوب وجاي في الطريق، تابعه من التطبيق",
        "تم تسليم طلبك بنجاح، نتمنى تقيم تجربتك في التطبيق",
        "فودافون: اتجددت باقتك بنجاح، لإدارة اشتراكاتك زور تطبيق أنا فودافون",
        "وي: عرض الإنترنت الأرضي الجديد، سرعات أعلى بنفس السعر، للاشتراك زور أقرب فرع",
        "يا ابني وصلت بخير، متقلقش عليا",
        "الاجتماع اتأجل لبكرة الساعة 12، اعتذر عن التغيير المفاجئ",
        "هات معاك 2 كيلو طماطم وانت جاي على البيت لو سمحت",
        "Happy birthday! Hope you have a great year ahead",
        "Meeting moved to 3pm tomorrow, same link",
    ]
    return out


EG_LEGIT_V2B = _v2_legit_lookalikes()


def main():
    legit = []
    scam = []
    for text, label, source in read_uci(os.path.join(DATA, "SMSSpamCollection")):
        (scam if label else legit).append((text, label, source))
    for r in read_arabic_spam(os.path.join(DATA, "Arabic_Spam_raw.csv")):
        (scam if r[1] else legit).append(r)
    for r in read_arabpython(os.path.join(DATA, "arabic_messages.csv")):
        (scam if r[1] else legit).append(r)
    for r in read_moz(os.path.join(DATA, "moz_smishing.csv")):
        (scam if r[1] else legit).append(r)
    for t in EG_SCAM + EG_SCAM_EXTRA + EG_SCAM_V2:
        scam.append((t, 1, "eg_synthetic"))
    for t in EG_LEGIT + EG_LEGIT_EXTRA + EG_LEGIT_V2 + EG_LEGIT_V2B:
        legit.append((t, 0, "eg_synthetic"))
    # verbatim phrases quoted in public Egyptian warnings (see EGYPT_PATTERNS.md)
    for t in ["مبروك كسبت جائزة", "مبروك كسبت جائزة مالية كبيرة اضغط هنا لاستلامها"]:
        scam.append((t, 1, "eg_public"))

    # cap the big English/multilingual scam corpora near 2.5x legit
    budget = int(len(legit) * 2.5) - len(scam)
    scam += read_imc25(os.path.join(DATA, "imc25_smishing.csv"), cap=int(budget * 0.7))
    scam += read_shaghayegh(os.path.join(DATA, "smishing_combined.csv"), cap=int(budget * 0.3))

    rows = legit + scam

    # de-duplicate identical texts
    seen = set()
    unique = []
    for text, label, source in rows:
        key = text.lower().strip()
        if key in seen:
            continue
        seen.add(key)
        unique.append((text, label, source))

    random.Random(42).shuffle(unique)
    out = os.path.join(DATA, "combined.csv")
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["text", "label", "source"])
        w.writerows(unique)

    from collections import Counter
    by_source = Counter(s for _, _, s in unique)
    by_label = Counter(l for _, l, _ in unique)
    print(f"wrote {len(unique)} rows -> {out}")
    print("by source:", dict(by_source))
    print("by label:", dict(by_label))


if __name__ == "__main__":
    main()

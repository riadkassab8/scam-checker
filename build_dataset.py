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
    for t in EG_SCAM + EG_SCAM_EXTRA:
        scam.append((t, 1, "eg_synthetic"))
    for t in EG_LEGIT + EG_LEGIT_EXTRA:
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

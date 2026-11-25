# Egyptian scam patterns, grounded in public warnings

Each pattern below comes from a public Egyptian source (official bank/telecom
warnings or news articles quoting them). The training examples in
`build_dataset.py` marked `eg_synthetic` are written from these documented
patterns — they are NOT real harvested messages. Anything marked `eg_public`
is a phrase quoted verbatim in a public source.

## P1. "مبروك كسبت جائزة" prize lure (banks)
Banque Misr and NBE warned about messages saying «مبروك كسبت جائزة» with
links asking for banking data to "receive the prize".
- https://www.elwatannews.com/news/details/8300596
- https://www.banker.news/145533
- https://www.elwatannews.com/news/details/6898635

## P2. Vodafone Cash / wallet impostors
Vodafone Egypt's official safety page: impostors pretend to be customer
service, say you won a gift, or that the wallet needs an update, and ask for
the PIN or a small "activation" transfer. Also: fake transfer receipts and
balance-screenshot tricks.
- https://web.vodafone.com.eg/ar/خليك-في-أمان
- https://www.aymany.com/2026/10/8.html
- https://www.elhayatnews.com/117594

## P3. Fake "purchase/transfer you didn't make" + cancel link
CBE and bank warnings: a message claims a purchase or transfer happened and
pushes a link "to cancel it", harvesting card data.
- https://www.elwatannews.com/news/details/8402014
- https://www.cbe.org.eg/ar/news-publications/news/2024/10/16/13/44/...

## P4. InstaPay "update your data" trick
CBE warning reported by Al-Masry Al-Youm: «احذفوا هذه الرسالة فورًا» —
messages pushing InstaPay users to fake update pages.
- https://www.almasryalyoum.com/news/details/4352093

## P5. Government/utility impersonation
NTRA (القومي لتنظيم الاتصالات) warned about fake messages impersonating
Egypt Post and other bodies with phishing links.
- https://www.fintechgate.net/190944
- https://www.almasryalyoum.com/news/details/4392167

## P6. Free-gift groups on Telegram/WhatsApp
CBE denied distributing free gifts; experts warned of gift scams running
through WhatsApp/Telegram groups.
- https://www.newsroom.info/394055

## P7. Common local lures seen across coverage
Housing-unit offers with deposits, job offers with registration fees,
parcel/customs fees, "رصيد مجاني" telecom offers, OTP requests.
- https://www.elwatannews.com/news/details/8262292
- https://www.elwatannews.com/news/details/8355644

## Verbatim quoted fragments (eg_public)
- «مبروك كسبت جائزة» (P1 sources)
- «حدث بياناتك» / «تفعيل الحساب» style phrasing (P2/P4 sources)

# OSINT evidence for the week 8 emulation plan

**Performed by:** Kazhymukan Boris (OSINT role) · **Date:** 2026-11-03

This file explains why the emulation plan in [`README.md`](README.md) is realistic. Every phase of the plan is backed by something we already observed (weeks 2–5) or by a public warning from a brand, KZ-CERT or the media. All of it is public and used for recognition and detection, not to reproduce an attack.

---

## 1. Public warnings: brands, KZ-CERT, media

| # | Brand | Source | Date | What it says | Plan phase |
|---|---|---|---|---|---|
| S1 | Kaspi | [Tengrinews: Kaspi.kz look-alike site found and blocked](https://tengrinews.kz/money/sait-dvoinik-kaspikz-nasli-i-zablokirovali-v-kazaxstane-375251/) | 2019-07-30 | `kaspi-bannk.com` was registered on 2019-07-29 and reported to KZ-CERT on the same day. The page asked for phone + password, then the **SMS code** | Resource Dev (T1583.001), Credential Access (T1056.003, T1111) |
| S2 | Kaspi | [Finratings: fake links in WhatsApp](https://finratings.kz/news/1265-kaspi-kz-moshenniki-rassylaiut-falshivye-ssylki-v-whatsapp/) | 2025-03-10 | Messages come from **hijacked accounts of people the victim knows** in WhatsApp/Telegram ("vote in a contest"). The fake site collects personal data and takes over the account | Initial Access (T1566.002 / T1660) |
| S3 | Kazpost | [Finratings: dangerous messages in the name of Kazpost](https://finratings.kz/news/3902-kazakhstantsam-prikhodiat-opasnye-soobshcheniia-ot-imeni-kazpochty/) | 2025-05-31 | Lure via SMS and e-mail: "parcel cannot be delivered due to an address error, follow the link". Kazpost's press service confirmed the messages are fraud | Initial Access (T1566.002) |
| S4 | Delivery services (generic) | [Finratings: fake delivery messages in Kazakhstan](https://finratings.kz/news/12562-moshenniki-rassylaiut-feikovye-soobshcheniia-o-dostavke-v-kazakhstane/) | 2026-03-15 | "Missed delivery" lure via SMS / messengers. The fake page copies courier-company design and steals full name, **IIN**, address, card data and a small "redelivery fee" | Initial Access, Credential Access (T1056.003) |
| S5 | eGov + banks | [Informburo: KZ-CERT found 200+ fraudulent resources](https://informburo.kz/novosti/kz-cert-vyyavil-bolee-200-moshennicheskih-resursov-ih-maskirovali-pod-sayty-bankov-i-egov.html) | 2019-01-22 | In about 3 weeks: 200+ resources, 67 of them phishing pages, imitating KZ banks, electronics shops and **eGov**. Lures: fake surveys, prizes and "payouts" requiring a fee | Resource Dev, Initial Access |
| S6 | Kazpost | [Finratings: fraudsters posing as Kazpost steal billions](https://finratings.kz/news/5126-moshenniki-pod-vidom-kazpochty-kradut-milliardy-u-kazakhstantsev/) | — | Scale of Kazpost-themed fraud | Impact / motivation |
| S7 | Couriers | [Kazinform: police warn about a new fraud scheme](https://www.inform.kz/ru/politsiya-preduprezhdaet-kazahstantsev-o-novoy-sheme-moshennichestva-0ed4b9) | — | Police warning on delivery/courier schemes | Initial Access |

> For CDEK we found **no official CDEK Kazakhstan warning** in open sources. Delivery-themed lures are described generically (S4). This is a gap, not proof that CDEK is not abused (see section 2: `cdekteam.ru` turned out to be a false positive).

## 2. Our own observed indicators (weeks 2 and 5)

### 2.1 Confirmed phishing domains, real feed (week 5)

Source: [`week-05/data/real/kz_hits.csv`](../week-05/data/real/kz_hits.csv), from the public feed `phishing-domains-ACTIVE.txt` (392,164 active domains). The rule was refined from 214 naive hits down to 14, and 4 of them were confirmed.

| Domain (defanged) | Brand | Why it is phishing | Plan phase |
|---|---|---|---|
| `kaspibank.auth-telegramm[.]ru` | Kaspi | Kaspi name + fake Telegram "auth" page on a .ru host | Resource Dev → Credential Access (account takeover, matches S2) |
| `kaspiy-delfin.tarho05[.]ru` | Kaspi | Kaspi-like label on a throw-away .ru subdomain | Resource Dev (T1583.001) |
| `kaspl[.]ga` | Kaspi | Typosquat `kaspi` → `kaspl` (i→l), free .ga TLD | Resource Dev (T1583.001) |
| `olxkz.pay-sacure4ds[.]ru` | OLX.kz | Fake "3-D Secure" payment page | Credential Access (T1056.003, T1111) |

### 2.2 Candidates checked and rejected (week 2)

| Domain | Result | Lesson for the plan |
|---|---|---|
| `cdekteam[.]ru` | **False positive**: 0/91 on VirusTotal, top-1M, registered since 2021-12-03, Tilda hosting (185.215.4.20, AS57724), corporate MX behind `mx.ms.bi.zone` | A brand keyword in a domain is not enough. Detection must check domain age and certificate type |
| `egov-kz-pay[.]online` | Cited in media as an eGov "payout" phishing site; 0/94 on VirusTotal, already offline | Phishing is short-lived. Reputation lags, so we detect on registration/CT logs instead |
| `kaspi.kz`, `kaspibank.kz`, `cdn-kaspi.kz` | Legitimate: DigiCert **OV** certificates, `O=Kaspi Bank, JSC` | Real brand = paid OV cert; phishing = free DV cert. Used as an allow-list |

Full details: [`week-02/README.md`](../week-02/README.md), [`week-02/data/relations.csv`](../week-02/data/relations.csv), [`week-02/evidence/`](../week-02/evidence/).

### 2.3 Global analogs (week 5)

The same lure types are widely used against similar global brands: PayPal ≈ Kaspi (1,078 domains), DHL/USPS ≈ Kazpost/CDEK (404 / 1,313), Gosuslugi ≈ eGov (16). The most common TLDs are `.top`, `.com`, `.cc`, `.ru`. This supports the "delivery" and "payment" lures in the plan.

### 2.4 MISP event (week 3)

[`week-03/misp-event-export.json`](../week-03/misp-event-export.json) contains IOCs created for the MISP lab (`kaspi-bonus-2026[.]com`, `eg0v-portal[.]kz`, `kazpost-delivery-track[.]net`, `185.120.10.45`, `193.100.20.15`). These are **lab/test indicators** and were not verified against public sources, so they are not used as evidence here.

## 3. Lure patterns (recognition level)

| Theme | Brand | Channel | Source |
|---|---|---|---|
| "Parcel not delivered / address error / missed delivery, pay a small fee" | Kazpost, couriers | SMS, e-mail, messengers | S3, S4, S7 |
| "Payout / bonus / prize from the state or bank" | eGov, Kaspi | Messengers, e-mail | S5, `egov-kz-pay.online` |
| "Vote in a contest" from a hijacked friend's account | Kaspi (account takeover) | WhatsApp, Telegram | S2 |
| Fake login → SMS-code page | Kaspi | Link to look-alike domain | S1 |
| Fake "3-D Secure" payment confirmation | OLX.kz | Link | week 5 |

## 4. What the OSINT tells the emulation plan

1. **The main goal is credentials, card data and OTP codes, not malware.** In every public case the victim types data into a web form (S1–S5). So in our plan, Credential Access (T1056.003, T1111) is the primary path and the endpoint implant branch (persistence → exfil) is the secondary one. The CALDERA part of week 8 emulates that secondary branch because it is the only part that can be safely emulated in a lab.
2. **Initial Access is mostly SMS/messengers (T1660, T1566.002), not corporate e-mail.** Most of this channel is invisible to a company SIEM, so detection must move upstream: CT logs, new domain registrations, brand allow-lists.
3. **Infrastructure is cheap and short-lived** (`.ga`, `.ru` subdomains, free DV certificates, sites already offline by the time they are scanned). IP blocking is weak because of shared hosting (Tilda / DDoS-Guard). Domains and certificates are better indicators.
4. **Exfiltration to Telegram is plausible** (`kaspibank.auth-telegramm.ru` imitates a Telegram auth page), so `api.telegram.org` from unusual hosts is included in [`detection.md`](detection.md).

## 5. Limitations

- Only open sources; no access to SMS/telecom data where most lures are delivered.
- Media dates range from 2019 to 2026; older cases show that the scheme is long-lived, but specific domains are long gone.
- No official CDEK Kazakhstan warning was found.
- All domains above are written defanged (`[.]`) and must not be opened outside a sandbox.

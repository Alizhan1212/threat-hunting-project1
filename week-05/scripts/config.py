"""
Week 05 - shared configuration for the lab log generator and the reference hunt.

Simulated network: "QazLogistics LLP", ~24 Windows workstations, one week of logs
(2026-09-28 .. 2026-10-04, Asia/Almaty UTC+05:00).

All phishing domains except the week-3 MISP indicator `kaspi-bonus-2026.com` are
invented for this lab. Their IPs use the documentation ranges reserved by RFC 5737
(198.51.100.0/24, 203.0.113.0/24), so nothing here points at a real host.
"""

# --- brands we defend (mirrors week-02/config/brands.json) --------------------
BRAND_KEYWORDS = ["kaspi", "egov", "kazpost", "post.kz", "cdek", "halyk", "homebank"]

# Official domains -> these must NOT be flagged (allow-list for the hunt)
OFFICIAL = [
    "kaspi.kz", "kaspibank.kz", "cdn-kaspi.kz",
    "egov.kz", "gov.kz",
    "post.kz", "kazpost.kz",
    "cdek.kz", "cdek.ru",
    "halykbank.kz", "homebank.kz",
]

# --- known-bad from our own CTI (week 3 MISP event) ---------------------------
KNOWN_BAD_DOMAINS = [
    "kaspi-bonus-2026.com",
    "eg0v-portal.kz",
    "kazpost-delivery-track.net",
]
KNOWN_BAD_IPS = ["185.120.10.45", "193.100.20.15"]

# --- real false positives our OSINT met in week 2 (benign look-alikes) --------
# Keeping them in the data proves the hunt can separate "contains the word" from "is phishing".
BENIGN_LOOKALIKES = [
    "cdekteam.ru",            # Russian site on Tilda, 0/91 on VirusTotal
    "egov.proteantech.in",    # Indian e-gov vendor
    "kolesa-darom.ru",        # Russian tyre shop ("kolesa" = wheels)
]

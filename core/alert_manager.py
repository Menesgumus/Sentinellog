# alert_manager.py — Alertleri yönetir, IP takibi yapar, CSV'ye yazar

import csv
import os
from datetime import datetime

CIKTI_KLASORU = "output"
CSV_DOSYASI = os.path.join(CIKTI_KLASORU, "rapor.csv")
IP_DOSYASI = os.path.join(CIKTI_KLASORU, "riskli_ipler.csv")

ip_skorlari = {}

SEVIYE_PUAN = {
    "DUSUK": 1,
    "ORTA": 3,
    "YUKSEK": 5
}


def klasor_hazirla():
    os.makedirs(CIKTI_KLASORU, exist_ok=True)


def ip_skoru_guncelle(ip, seviye):
    puan = SEVIYE_PUAN.get(seviye, 1)
    ip_skorlari[ip] = ip_skorlari.get(ip, 0) + puan
    return ip_skorlari[ip]


def seviye_belirle(skor):
    if skor >= 15:
        return "KRITIK"
    elif skor >= 8:
        return "YUKSEK"
    elif skor >= 4:
        return "ORTA"
    else:
        return "DUSUK"


def _csv_yaz(dosya_yolu, satir):
    dosya_var = os.path.exists(dosya_yolu)
    with open(dosya_yolu, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=satir.keys())
        if not dosya_var:
            writer.writeheader()
        writer.writerow(satir)


def alert_isle(alert):
    klasor_hazirla()

    ip = alert.get("src_ip", "-")
    seviye = alert.get("seviye", "DUSUK")
    zaman = alert.get("zaman") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if ip != "-":
        skor = ip_skoru_guncelle(ip, seviye)
        tehdit = seviye_belirle(skor)
    else:
        skor = 0
        tehdit = seviye

    print(f"\n{'='*60}")
    print(f"ALERT: {alert['kural_adi']}")
    print(f"   Seviye  : {seviye}")
    print(f"   IP      : {ip}")
    print(f"   Zaman   : {zaman}")
    print(f"   Açıklama: {alert['aciklama']}")
    print(f"   IP Skoru: {skor} → Tehdit: {tehdit}")
    print(f"   Log     : {alert.get('ham_log', '')[:80]}")
    print(f"{'='*60}")

    csv_satiri = {
        "zaman": zaman,
        "kural_id": alert.get("kural_id", ""),
        "kural_adi": alert.get("kural_adi", ""),
        "seviye": seviye,
        "src_ip": ip,
        "aciklama": alert.get("aciklama", ""),
        "ip_skoru": skor,
        "tehdit_seviyesi": tehdit,
        "ham_log": alert.get("ham_log", "")
    }
    _csv_yaz(CSV_DOSYASI, csv_satiri)

    if ip != "-":
        _csv_yaz(IP_DOSYASI, {
            "zaman": zaman,
            "ip": ip,
            "kural": alert.get("kural_adi", ""),
            "seviye": seviye,
            "skor": skor,
            "tehdit": tehdit
        })
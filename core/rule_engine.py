# rule_engine.py — YAML kurallarını log satırına uygular

import re
import yaml

KURAL_DOSYASI = "config/rules.yaml"

def kurallari_yukle() -> list:
    """
    config/rules.yaml dosyasını okur ve kuralları liste olarak döner.
    """
    with open(KURAL_DOSYASI, "r", encoding="utf-8") as dosya:
        icerik = yaml.safe_load(dosya)
    return icerik.get("kurallar", [])


def kurallari_uygula(log_verisi: dict, kurallar: list) -> list:
    """
    Bir log satırını alır, tüm kurallara karşı test eder.
    Eşleşen her kural için bir alert sözlüğü üretir.
    """
    alertler = []

    log_turu = log_verisi.get("log_turu", "")
    mesaj = log_verisi.get("mesaj", "")

    if not mesaj:
        return alertler

    for kural in kurallar:

        # Kural bu log türüne ait değilse atla
        if kural.get("log_turu") != log_turu:
            continue

        # Regex desenini log mesajına uygula
        eslesme = re.search(kural["desen"], mesaj)

        if eslesme:
            # Eşleşen grupları al (src_ip, kullanici gibi)
            gruplar = eslesme.groupdict()

            alert = {
                "kural_id": kural["id"],
                "kural_adi": kural["ad"],
                "seviye": kural["seviye"],
                "aciklama": kural["aciklama"],
                "log_turu": log_turu,
                "zaman": log_verisi.get("zaman", ""),
                "src_ip": gruplar.get("src_ip", "-"),
                "detay": gruplar,
                "ham_log": log_verisi.get("ham", "")
            }

            alertler.append(alert)

    return alertler
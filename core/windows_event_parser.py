# windows_event_parser.py — Windows Event Log okuyucu ve parser

import re
import datetime

# Windows Event ID → açıklama eşlemesi
EVENT_ID_MAP = {
    4625: {"mesaj": "Basarisiz oturum acma",           "seviye": "YUKSEK"},
    4624: {"mesaj": "Basarili oturum acma",             "seviye": "DUSUK"},
    4648: {"mesaj": "Acik kimlik bilgisi ile giris",    "seviye": "ORTA"},
    4720: {"mesaj": "Yeni kullanici hesabi olusturuldu","seviye": "YUKSEK"},
    4728: {"mesaj": "Guvenlik grubuna uye eklendi",     "seviye": "YUKSEK"},
    4732: {"mesaj": "Yerel gruba uye eklendi",          "seviye": "ORTA"},
    4672: {"mesaj": "Yonetici ayricaligi atandi",       "seviye": "YUKSEK"},
    4698: {"mesaj": "Zamanlanmis gorev olusturuldu",    "seviye": "YUKSEK"},
    4702: {"mesaj": "Zamanlanmis gorev guncellendi",    "seviye": "ORTA"},
    7045: {"mesaj": "Yeni servis kuruldu",              "seviye": "ORTA"},
    7036: {"mesaj": "Servis durumu degisti",            "seviye": "DUSUK"},
    1000: {"mesaj": "Uygulama hatasi",                  "seviye": "DUSUK"},
}


def pywin32_yuklu() -> bool:
    """pywin32 kütüphanesinin yüklü olup olmadığını kontrol eder."""
    try:
        import win32evtlog
        return True
    except ImportError:
        return False


def event_log_oku(kanal: str = "Security", max_kayit: int = 500) -> list:
    """
    Windows Event Log'dan kayıt okur.
    pywin32 yüklü değilse boş liste döner.
    """
    if not pywin32_yuklu():
        print("[HATA] pywin32 yüklü değil. Yüklemek için: pip install pywin32")
        return []

    import win32evtlog
    import win32evtlogutil

    kayitlar = []
    try:
        handle = win32evtlog.OpenEventLog(None, kanal)
        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                 win32evtlog.EVENTLOG_SEQUENTIAL_READ)

        okunan = 0
        while okunan < max_kayit:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
            for event in events:
                if okunan >= max_kayit:
                    break
                kayit = _event_parse(event, kanal)
                if kayit:
                    kayitlar.append(kayit)
                okunan += 1

        win32evtlog.CloseEventLog(handle)

    except Exception as e:
        print(f"[HATA] Event Log okunamadı ({kanal}): {e}")

    return kayitlar


def _event_parse(event, kanal: str) -> dict:
    """Tek bir Windows Event kaydını SentinelLog formatına dönüştürür."""
    try:
        import win32evtlogutil
        event_id = event.EventID & 0xFFFF
        zaman    = event.TimeGenerated.Format()
        kaynak   = event.SourceName
        bilgi    = EVENT_ID_MAP.get(event_id, {})

        try:
            mesaj = win32evtlogutil.SafeFormatMessage(event, kanal)
        except Exception:
            mesaj = f"Event ID: {event_id} | Kaynak: {kaynak}"

        return {
            "log_turu": "winevent",
            "platform": "windows",
            "zaman":    zaman,
            "event_id": event_id,
            "kanal":    kanal,
            "kaynak":   kaynak,
            "seviye":   bilgi.get("seviye", "DUSUK"),
            "olay":     bilgi.get("mesaj", f"Event {event_id}"),
            "mesaj":    mesaj[:500] if mesaj else "",
            "ham":      f"[{kanal}] EventID:{event_id} {kaynak} {zaman}",
            "src_ip":   "-"
        }
    except Exception:
        return {}


def canli_event_izle(kanal: str, kuyruk, aktif_flag: list,
                     kurallar: list, anomaly):
    """
    Windows Event Log'u canlı izler.
    aktif_flag: [True] → devam, [False] → dur
    """
    if not pywin32_yuklu():
        kuyruk.put(("bilgi", "[HATA] pywin32 yüklü değil."))
        return

    import win32evtlog
    import time
    from core.rule_engine import kurallari_uygula
    from core.alert_manager import alert_isle

    try:
        handle = win32evtlog.OpenEventLog(None, kanal)
        flags  = (win32evtlog.EVENTLOG_FORWARDS_READ |
                  win32evtlog.EVENTLOG_SEQUENTIAL_READ)

        while aktif_flag[0]:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if events:
                for event in events:
                    log_verisi = _event_parse(event, kanal)
                    if not log_verisi:
                        continue
                    kural_alertleri   = kurallari_uygula(log_verisi, kurallar)
                    anomali_alertleri = anomaly.log_isle(log_verisi, kural_alertleri)
                    for alert in kural_alertleri + anomali_alertleri:
                        alert["kaynak_dosya"] = kanal
                        alert_isle(alert)
                        kuyruk.put(("alert", alert))
            else:
                time.sleep(1)

        win32evtlog.CloseEventLog(handle)

    except Exception as e:
        kuyruk.put(("bilgi", f"[HATA] Event Log izleme hatası: {e}"))
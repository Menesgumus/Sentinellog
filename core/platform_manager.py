# platform_manager.py — Platform tespiti ve log yolu yönetimi

import os
import platform

SISTEM = platform.system()  # "Windows", "Linux", "Darwin"


# ── Linux log yolları ─────────────────────────────────────────────────
LINUX_LOG_YOLLARI = {
    "auth":   [
        "/var/log/auth.log",
        "/var/log/secure",          # CentOS / RHEL
    ],
    "syslog": [
        "/var/log/syslog",
        "/var/log/messages",        # CentOS / RHEL
    ],
    "access": [
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",  # CentOS / RHEL
        "/var/log/nginx/access.log",
    ],
    "nginx":  [
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
    ],
    "ufw":    [
        "/var/log/ufw.log",
    ],
    "kern":   [
        "/var/log/kern.log",
    ],
}

# ── Windows log yolları ───────────────────────────────────────────────
WINDOWS_LOG_YOLLARI = {
    "system":   "System",      # Windows Event Log kanal adları
    "security": "Security",
    "app":      "Application",
}


def sistem_tespit() -> str:
    """
    Çalışan işletim sistemini döner.
    Dönüş: "linux", "windows", "macos", "bilinmiyor"
    """
    if SISTEM == "Linux":
        return "linux"
    elif SISTEM == "Windows":
        return "windows"
    elif SISTEM == "Darwin":
        return "macos"
    return "bilinmiyor"


def linux_log_yollarini_tara() -> dict:
    """
    Linux'ta mevcut log dosyalarını tarar.
    Sadece gerçekten var olan dosyaları döner.
    Dönüş: {"auth": "/var/log/auth.log", "nginx": "/var/log/nginx/access.log", ...}
    """
    bulunanlar = {}
    for log_turu, yollar in LINUX_LOG_YOLLARI.items():
        for yol in yollar:
            if os.path.exists(yol):
                bulunanlar[log_turu] = yol
                break  # İlk bulunanı al
    return bulunanlar


def windows_kanallari_listele() -> list:
    """
    Windows Event Log kanallarını listeler.
    pywin32 yüklü değilse boş liste döner.
    """
    try:
        import win32evtlog
        kanallar = []
        for kanal_adi, kanal in WINDOWS_LOG_YOLLARI.items():
            kanallar.append({
                "id": kanal_adi,
                "ad": kanal,
                "log_turu": "winevent"
            })
        return kanallar
    except ImportError:
        return []


def mevcut_loglar() -> dict:
    """
    Platforma göre mevcut logları döner.
    Linux  → dosya yolları
    Windows → Event Log kanal listesi
    """
    sistem = sistem_tespit()

    if sistem == "linux":
        return {
            "platform": "linux",
            "loglar": linux_log_yollarini_tara()
        }
    elif sistem == "windows":
        return {
            "platform": "windows",
            "kanallar": windows_kanallari_listele()
        }
    elif sistem == "macos":
        # macOS Linux'a benzer yapı
        return {
            "platform": "macos",
            "loglar": {
                k: v for k, yollar in LINUX_LOG_YOLLARI.items()
                for v in yollar if os.path.exists(v)
            }
        }
    return {"platform": "bilinmiyor", "loglar": {}}
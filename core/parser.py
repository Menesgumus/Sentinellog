# parser.py — Ham log satırını anlamlı parçalara ayırır

import re
from datetime import datetime

def log_parcala(satir: str, log_turu: str) -> dict:
    """
    Ham log satırını alır, log türüne göre parçalara ayırır.
    Her zaman bir sözlük döner. Tanınamayan satırlar 'ham' olarak döner.
    """

    satir = satir.strip()
    if not satir:
        return {}

    # Auth.log formatı
    # Örnek: Jan 10 03:45:01 server sshd[1234]: Failed password for root from 192.168.1.1
    if log_turu == "auth":
        desen = r"(?P<ay>\w+)\s+(?P<gun>\d+)\s+(?P<saat>[\d:]+)\s+(?P<sunucu>\S+)\s+(?P<servis>\S+):\s+(?P<mesaj>.+)"
        eslesme = re.match(desen, satir)
        if eslesme:
            return {
                "log_turu": "auth",
                "zaman": f"{eslesme.group('ay')} {eslesme.group('gun')} {eslesme.group('saat')}",
                "sunucu": eslesme.group("sunucu"),
                "servis": eslesme.group("servis"),
                "mesaj": eslesme.group("mesaj"),
                "ham": satir
            }

    # Access.log formatı
    # Örnek: 192.168.1.1 - - [10/Jan/2024:03:45:01 +0300] "GET /admin HTTP/1.1" 401 512
    if log_turu == "access":
        desen = r'(?P<src_ip>[\d\.]+) - - \[(?P<zaman>[^\]]+)\] "(?P<istek>[^"]+)" (?P<kod>\d+) (?P<boyut>\d+)'
        eslesme = re.match(desen, satir)
        if eslesme:
            return {
                "log_turu": "access",
                "src_ip": eslesme.group("src_ip"),
                "zaman": eslesme.group("zaman"),
                "istek": eslesme.group("istek"),
                "kod": eslesme.group("kod"),
                "boyut": eslesme.group("boyut"),
                "mesaj": satir,
                "ham": satir
            }

    # UFW.log formatı
    # Örnek: Jan 10 03:45:01 server kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=5.6.7.8
    if log_turu == "ufw":
        desen = r"(?P<ay>\w+)\s+(?P<gun>\d+)\s+(?P<saat>[\d:]+)\s+(?P<sunucu>\S+)\s+kernel:.*\[(?P<eylem>UFW \w+)\](?P<detay>.+)"
        eslesme = re.match(desen, satir)
        if eslesme:
            return {
                "log_turu": "ufw",
                "zaman": f"{eslesme.group('ay')} {eslesme.group('gun')} {eslesme.group('saat')}",
                "eylem": eslesme.group("eylem"),
                "detay": eslesme.group("detay"),
                "mesaj": satir,
                "ham": satir
            }

    # Hiçbir formata uymadıysa ham olarak döndür
    return {
        "log_turu": log_turu,
        "mesaj": satir,
        "ham": satir
    }
# anomaly_engine.py — İstatistiksel kayan pencere anomali motoru

# Kural motoru bireysel satırlara regex uygular.
# Anomali motoru ise zaman içindeki birikimi izler:
#   - "Bu IP son 60 saniyede kaç kez başarısız giriş yaptı?"
#   - "Bu IP kaç farklı porta bağlanmaya çalıştı?"
#
# Sliding Window yaklaşımı:
#   Her (IP, olay_tipi) çifti için bir zaman damgalı kuyruk tutulur.
#   Her yeni olayda eski kayıtlar (pencere dışındakiler) temizlenir.
#   Kalan sayı eşiği aşarsa anomali üretilir.

import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

# Ay kısaltmaları → numara (log'larda İngilizce ay adı gelir)
AY_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}


def _zaman_parse(zaman_str: str) -> datetime:
    """
    Log zaman stringini datetime nesnesine çevirir.
    Desteklenen formatlar:
      - Auth/UFW: "Jan 10 03:45:01"
      - Access:   "10/Jan/2024:03:45:01 +0300"
    Tanınamayan formatlarda şimdiki zamanı döner.
    """
    if not zaman_str:
        return datetime.now()
    try:
        # Access log formatı: "10/Jan/2024:03:45:01 +0300"
        if "/" in zaman_str:
            m = re.match(r"(\d+)/(\w+)/(\d+):(\d+):(\d+):(\d+)", zaman_str)
            if m:
                gun, ay_str, yil, saat, dakika, saniye = m.groups()
                ay = AY_MAP.get(ay_str, datetime.now().month)
                return datetime(int(yil), ay, int(gun),
                                int(saat), int(dakika), int(saniye))
        # Auth/UFW formatı: "Jan 10 03:45:01"
        parcalar = zaman_str.split()
        if len(parcalar) == 3:
            ay = AY_MAP.get(parcalar[0], datetime.now().month)
            gun = int(parcalar[1])
            s, dk, sn = parcalar[2].split(":")
            return datetime(datetime.now().year, ay, gun,
                            int(s), int(dk), int(sn))
    except Exception:
        pass
    return datetime.now()


class AnomalyEngine:
    """
    Kayan zaman penceresi (sliding window) tabanlı anomali tespit motoru.

    Çalışma mantığı:
      1. Her log satırı için log_isle() çağrılır.
      2. IP ve olay tipine göre olaylar bir kuyrukta biriktirilir.
      3. Her kontrol öncesi pencere dışındaki eski olaylar silinir.
      4. Kalan olay sayısı eşiği aştıysa → anomali alert üretilir.
      5. Spam önleme: Aynı IP / aynı kural için bekleme süresi uygulanır.
    """

    # Anomali kuralları — genişletilebilir yapı
    ANOMALI_KURALLARI = [
        {
            "id": "ANOM_SSH_BRUTE",
            "ad": "SSH Brute Force Anomalisi",
            "olay_tipi": "ssh_hatali",
            "log_turu": "auth",
            "esik": 5,          # kaç olay
            "pencere": 60,      # kaç saniye içinde
            "spam_bekleme": 30, # aynı IP için kaç saniye sonra tekrar tetiklensin
            "seviye": "KRITIK",
            "aciklama": "{pencere}sn içinde {sayi} başarısız SSH denemesi (eşik: {esik})"
        },
        {
            "id": "ANOM_PORT_TARAMA",
            "ad": "Port Tarama Anomalisi",
            "olay_tipi": "ufw_engel",
            "log_turu": "ufw",
            "esik": 8,
            "pencere": 60,
            "spam_bekleme": 30,
            "seviye": "YUKSEK",
            "aciklama": "{pencere}sn içinde {sayi} UFW engeli — port tarama şüphesi"
        },
        {
            "id": "ANOM_PORT_TARAMA_DAGITIK",
            "ad": "Dağıtık Port Tarama",
            "olay_tipi": "ufw_farkli_port",   # farklı mantık: tekil port sayısı
            "log_turu": "ufw",
            "esik": 5,
            "pencere": 120,
            "spam_bekleme": 60,
            "seviye": "YUKSEK",
            "aciklama": "{pencere}sn içinde {sayi} farklı hedef porta bağlantı denemesi"
        },
        {
            "id": "ANOM_HTTP_CREDENTIAL",
            "ad": "HTTP Credential Stuffing",
            "olay_tipi": "http_yetkisiz",
            "log_turu": "access",
            "esik": 8,
            "pencere": 60,
            "spam_bekleme": 30,
            "seviye": "YUKSEK",
            "aciklama": "{pencere}sn içinde {sayi} yetkisiz HTTP erişimi (credential stuffing şüphesi)"
        },
    ]

    def __init__(self):
        self.aktif = True

        # Olay geçmişi: {(ip, olay_tipi): deque([(datetime, ek_bilgi), ...])}
        self._olaylar: dict = defaultdict(deque)

        # Spam önleme: {(ip, kural_id): son_tetik_datetime}
        self._tetiklendi: dict = {}

        print("[AnomalyEngine] Kayan pencere anomali motoru aktif.")

    # ------------------------------------------------------------------ #
    # Ana giriş noktası                                                    #
    # ------------------------------------------------------------------ #

    def log_isle(self, log_verisi: dict, kural_alertleri: list) -> list:
        """
        Tek log satırını işler.

        Parametreler:
          log_verisi      — parser.py'den gelen sözlük
          kural_alertleri — rule_engine.py'nin bu satır için ürettiği alertler

        Döner:
          Anomali alert sözlüklerinden oluşan liste (boş olabilir).
        """
        if not self.aktif:
            return []

        log_turu = log_verisi.get("log_turu", "")
        zaman_str = log_verisi.get("zaman", "")
        simdi = _zaman_parse(zaman_str)
        mesaj = log_verisi.get("mesaj", "") or log_verisi.get("ham", "")

        # IP adresini belirle: önce kural alertlerinden, yoksa log'dan
        src_ip = self._ip_cikart(log_verisi, kural_alertleri)
        if not src_ip:
            return []

        # Bu log satırı için olayları kaydet
        self._olay_kaydet(log_turu, src_ip, mesaj, simdi)

        # Tüm anomali kurallarını kontrol et
        return self._kontrol_et(log_turu, src_ip, zaman_str, simdi, log_verisi)

    def sifirla(self):
        """Tüm birikim ve tetik geçmişini temizler (yeni analiz seansı için)."""
        self._olaylar.clear()
        self._tetiklendi.clear()

    # ------------------------------------------------------------------ #
    # İç yardımcı metodlar                                                 #
    # ------------------------------------------------------------------ #

    def _ip_cikart(self, log_verisi: dict, kural_alertleri: list) -> str | None:
        """En güvenilir src_ip kaynağını bulur."""
        # Önce kural alertlerinden dene
        for alert in kural_alertleri:
            ip = alert.get("src_ip", "-")
            if ip and ip != "-":
                return ip

        # Log'un mesajından regex ile dene
        mesaj = log_verisi.get("mesaj", "") or log_verisi.get("ham", "")
        m = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", mesaj)
        if m:
            return m.group(1)

        # UFW formatında SRC= alanı
        m = re.search(r"SRC=(\d{1,3}(?:\.\d{1,3}){3})", mesaj)
        if m:
            return m.group(1)

        # Access log: satır başındaki IP
        m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})", mesaj)
        if m:
            return m.group(1)

        return None

    def _olay_kaydet(self, log_turu: str, ip: str, mesaj: str, simdi: datetime):
        """Gelen log satırını ilgili olay kuyruğuna ekler."""
        if log_turu == "auth":
            if re.search(r"Failed password", mesaj):
                self._olaylar[(ip, "ssh_hatali")].append((simdi, mesaj[:60]))

        elif log_turu == "ufw":
            # Toplam UFW engeli sayısı
            self._olaylar[(ip, "ufw_engel")].append((simdi, ""))

            # Hedef port — dağıtık tarama tespiti için
            m = re.search(r"DPT=(\d+)", mesaj)
            port = m.group(1) if m else "?"
            self._olaylar[(ip, "ufw_farkli_port")].append((simdi, port))

        elif log_turu == "access":
            if re.search(r'" (401|403)', mesaj):
                self._olaylar[(ip, "http_yetkisiz")].append((simdi, ""))

    def _pencere_temizle(self, ip: str, olay_tipi: str,
                         pencere: int, simdi: datetime):
        """Pencere dışındaki eski olayları siler."""
        esik_zaman = simdi - timedelta(seconds=pencere)
        kuyruk = self._olaylar[(ip, olay_tipi)]
        while kuyruk and kuyruk[0][0] < esik_zaman:
            kuyruk.popleft()

    def _spam_kontrol(self, ip: str, kural_id: str,
                      simdi: datetime, bekleme: int) -> bool:
        """
        True döner → tetiklenebilir (yeterince zaman geçmiş).
        False döner → spam, bu sefere atla.
        """
        anahtar = (ip, kural_id)
        son = self._tetiklendi.get(anahtar)
        if son and (simdi - son).total_seconds() < bekleme:
            return False
        self._tetiklendi[anahtar] = simdi
        return True

    def _kontrol_et(self, log_turu: str, ip: str,
                    zaman_str: str, simdi: datetime,
                    log_verisi: dict) -> list:
        """Bu log türüne ait tüm anomali kurallarını değerlendirir."""
        anomaliler = []

        for kural in self.ANOMALI_KURALLARI:
            if kural["log_turu"] != log_turu:
                continue

            olay_tipi = kural["olay_tipi"]
            pencere   = kural["pencere"]
            esik      = kural["esik"]

            self._pencere_temizle(ip, olay_tipi, pencere, simdi)
            kuyruk = self._olaylar[(ip, olay_tipi)]

            # Dağıtık port taraması için tekil port sayısına bak
            if olay_tipi == "ufw_farkli_port":
                sayi = len(set(bilgi for _, bilgi in kuyruk))
            else:
                sayi = len(kuyruk)

            if sayi < esik:
                continue

            if not self._spam_kontrol(ip, kural["id"], simdi, kural["spam_bekleme"]):
                continue

            anomaliler.append({
                "kural_id":  kural["id"],
                "kural_adi": kural["ad"],
                "seviye":    kural["seviye"],
                "aciklama":  kural["aciklama"].format(
                    sayi=sayi, esik=esik, pencere=pencere
                ),
                "log_turu":  log_turu,
                "zaman":     zaman_str or simdi.strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip":    ip,
                "detay":     {"sayi": sayi, "esik": esik, "pencere": pencere},
                "ham_log":   log_verisi.get("ham", ""),
                "anomali":   True       # Kural alertlerinden ayırt etmek için
            })

        return anomaliler
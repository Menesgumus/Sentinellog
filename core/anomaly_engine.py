# anomaly_engine.py — Anomali tespit motoru (şu an iskelet, ML sonra eklenecek)

# Bu dosya şu an sadece arayüzü tanımlıyor.
# İleride Isolation Forest veya benzeri bir ML modeli buraya eklenecek.
# Mevcut sistem bu dosyayı çağırıyor ama henüz alert üretmiyor.

class AnomalyEngine:

    def __init__(self):
        # İleride model burada yüklenecek
        self.aktif = False
        print("[AnomalyEngine] ML motoru şu an pasif. İleride aktif edilecek.")

    def egit(self, log_verileri: list):
        """
        Normal davranış örüntüsünü öğrenir.
        Şu an boş — ileride doldurulacak.
        """
        pass

    def kontrol_et(self, log_verisi: dict) -> dict | None:
        """
        Bir log satırını alır, anomali var mı diye kontrol eder.
        Şu an her zaman None döner (anomali yok).
        İleride anomali tespit ederse alert sözlüğü dönecek.
        """
        return None
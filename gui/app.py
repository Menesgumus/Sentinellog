# gui/app.py — SentinelLog Ana Arayüz

import tkinter as tk
from tkinter import filedialog, scrolledtext
import threading
import queue
import os
import sys
import yaml

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.parser import log_parcala
from core.rule_engine import kurallari_yukle, kurallari_uygula
from core.alert_manager import alert_isle, ip_skorlari
from core.anomaly_engine import AnomalyEngine

RENKLER = {
    "bg":         "#1e1e1e",
    "panel":      "#252526",
    "kenar":      "#3c3c3c",
    "yazi":       "#d4d4d4",
    "baslik":     "#ffffff",
    "KRITIK":     "#ff4444",
    "YUKSEK":     "#ff8c00",
    "ORTA":       "#ffd700",
    "DUSUK":      "#4ec94e",
    "buton":      "#0e639c",
    "buton_yazi": "#ffffff"
}


class SentinelLogApp:

    def __init__(self, root):
        self.root = root
        self.root.title("SentinelLog — Log Analiz ve İzleme Aracı")
        self.root.geometry("1100x700")
        self.root.configure(bg=RENKLER["bg"])
        self.root.minsize(900, 600)

        self.kurallar = kurallari_yukle()
        self.anomaly = AnomalyEngine()
        self.kuyruk = queue.Queue()
        self.canli_thread = None
        self.canli_aktif = False
        self.alert_sayisi = 0

        self._arayuz_kur()
        self.root.after(100, self._kuyruk_kontrol)

    def _arayuz_kur(self):
        baslik = tk.Frame(self.root, bg="#0e639c", height=50)
        baslik.pack(fill="x")
        baslik.pack_propagate(False)

        tk.Label(
            baslik, text="🛡  SentinelLog",
            font=("Segoe UI", 16, "bold"),
            bg="#0e639c", fg="white"
        ).pack(side="left", padx=15, pady=10)

        tk.Label(
            baslik, text=f"Platform: {sys.platform.upper()}",
            font=("Segoe UI", 9),
            bg="#0e639c", fg="#cce4f7"
        ).pack(side="right", padx=15)

        icerik = tk.Frame(self.root, bg=RENKLER["bg"])
        icerik.pack(fill="both", expand=True)

        self._sol_menu_kur(icerik)
        self._sag_panel_kur(icerik)
        self._alt_bar_kur()

    def _sol_menu_kur(self, parent):
        sol = tk.Frame(parent, bg=RENKLER["panel"], width=220)
        sol.pack(side="left", fill="y")
        sol.pack_propagate(False)

        tk.Label(
            sol, text="İŞLEMLER",
            font=("Segoe UI", 9, "bold"),
            bg=RENKLER["panel"], fg="#858585"
        ).pack(anchor="w", padx=15, pady=(20, 5))

        butonlar = [
            ("📂  Dosya Analizi",   self._dosya_analiz),
            ("🔴  Canlı İzleme",    self._canli_baslat),
            ("⏹  İzlemeyi Durdur", self._canli_durdur),
            ("📝  Kural Editörü",   self._kural_editor_ac),
            ("🗑  Ekranı Temizle",  self._ekrani_temizle),
        ]

        for metin, komut in butonlar:
            tk.Button(
                sol, text=metin, command=komut,
                bg=RENKLER["buton"], fg=RENKLER["buton_yazi"],
                font=("Segoe UI", 10), relief="flat",
                cursor="hand2", padx=10, pady=8, anchor="w"
            ).pack(fill="x", padx=10, pady=3)

        tk.Label(
            sol, text="RİSKLİ IP'LER",
            font=("Segoe UI", 9, "bold"),
            bg=RENKLER["panel"], fg="#858585"
        ).pack(anchor="w", padx=15, pady=(25, 5))

        self.ip_listesi = tk.Listbox(
            sol, bg=RENKLER["bg"], fg=RENKLER["yazi"],
            font=("Consolas", 9), relief="flat",
            selectbackground="#0e639c", height=12
        )
        self.ip_listesi.pack(fill="x", padx=10)

    def _sag_panel_kur(self, parent):
        sag = tk.Frame(parent, bg=RENKLER["bg"])
        sag.pack(side="left", fill="both", expand=True)

        tk.Label(
            sag, text="ALERT AKIŞI",
            font=("Segoe UI", 9, "bold"),
            bg=RENKLER["bg"], fg="#858585"
        ).pack(anchor="w", padx=15, pady=(15, 5))

        self.alert_alani = scrolledtext.ScrolledText(
            sag, bg=RENKLER["bg"], fg=RENKLER["yazi"],
            font=("Consolas", 10), relief="flat",
            state="disabled", wrap="word"
        )
        self.alert_alani.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.alert_alani.tag_config("KRITIK", foreground=RENKLER["KRITIK"])
        self.alert_alani.tag_config("YUKSEK", foreground=RENKLER["YUKSEK"])
        self.alert_alani.tag_config("ORTA",   foreground=RENKLER["ORTA"])
        self.alert_alani.tag_config("DUSUK",  foreground=RENKLER["DUSUK"])
        self.alert_alani.tag_config("BILGI",  foreground="#858585")

    def _alt_bar_kur(self):
        alt = tk.Frame(self.root, bg=RENKLER["kenar"], height=28)
        alt.pack(fill="x", side="bottom")
        alt.pack_propagate(False)

        self.durum_label = tk.Label(
            alt, text="Hazır",
            font=("Segoe UI", 9),
            bg=RENKLER["kenar"], fg=RENKLER["yazi"]
        )
        self.durum_label.pack(side="left", padx=10, pady=4)

        self.sayac_label = tk.Label(
            alt, text="Toplam Alert: 0",
            font=("Segoe UI", 9),
            bg=RENKLER["kenar"], fg=RENKLER["yazi"]
        )
        self.sayac_label.pack(side="right", padx=10, pady=4)

    def _alert_yaz(self, alert: dict):
        seviye = alert.get("seviye", "DUSUK")
        self.alert_sayisi += 1
        self.sayac_label.config(text=f"Toplam Alert: {self.alert_sayisi}")

        kaynak = alert.get("kaynak_dosya", "")
        kaynak_str = f"[{kaynak}] " if kaynak else ""
        satir = (
            f"[{self.alert_sayisi}] {kaynak_str}{alert.get('zaman', '')} | "
            f"{seviye} | "
            f"IP: {alert.get('src_ip', '-')} | "
            f"{alert.get('kural_adi', '')} | "
            f"{alert.get('aciklama', '')}\n"
        )

        self.alert_alani.config(state="normal")
        self.alert_alani.insert("end", satir, seviye)
        self.alert_alani.see("end")
        self.alert_alani.config(state="disabled")
        self._ip_guncelle(alert.get("src_ip", "-"), seviye)

    def _ip_guncelle(self, ip: str, seviye: str):
        if ip == "-":
            return
        mevcut = list(self.ip_listesi.get(0, "end"))
        for i, item in enumerate(mevcut):
            if ip in item:
                self.ip_listesi.delete(i)
                break
        skor = ip_skorlari.get(ip, 0)
        self.ip_listesi.insert(0, f"{ip} [{skor}]")

    def _bilgi_yaz(self, mesaj: str):
        self.alert_alani.config(state="normal")
        self.alert_alani.insert("end", f"→ {mesaj}\n", "BILGI")
        self.alert_alani.see("end")
        self.alert_alani.config(state="disabled")

    def _dosya_analiz(self):
        dosyalar = filedialog.askopenfilenames(
            title="Log dosyalarını seç (birden fazla seçebilirsin)",
            filetypes=[("Log dosyaları", "*.log"), ("Tüm dosyalar", "*.*")]
        )
        if not dosyalar:
            return
        self.durum_label.config(text=f"Analiz ediliyor: {len(dosyalar)} dosya")
        self._bilgi_yaz(f"{len(dosyalar)} dosya analiz edilecek.")
        t = threading.Thread(target=self._coklu_analiz_worker, args=(dosyalar,), daemon=True)
        t.start()

    def _analiz_worker(self, dosya_yolu: str):
        pass  # artık _coklu_analiz_worker kullanılıyor

    def _coklu_analiz_worker(self, dosyalar: tuple):
        toplam = 0
        for dosya_yolu in dosyalar:
            ad = os.path.basename(dosya_yolu).lower()
            if "auth" in ad:
                log_turu = "auth"
            elif "access" in ad:
                log_turu = "access"
            elif "ufw" in ad:
                log_turu = "ufw"
            else:
                log_turu = "auth"

            sayac = 0
            self.kuyruk.put(("bilgi", f"[{ad}] analiz başladı..."))

            with open(dosya_yolu, "r", encoding="utf-8", errors="ignore") as f:
                for satir in f:
                    log_verisi = log_parcala(satir, log_turu)
                    if not log_verisi:
                        continue
                    alertler = kurallari_uygula(log_verisi, self.kurallar)
                    for alert in alertler:
                        alert["kaynak_dosya"] = ad  # hangi dosyadan geldiği
                        alert_isle(alert)
                        self.kuyruk.put(("alert", alert))
                        sayac += 1

            self.kuyruk.put(("bilgi", f"[{ad}] tamamlandı → {sayac} alert"))
            toplam += sayac

        self.kuyruk.put(("bilgi", f"Tüm dosyalar tamamlandı. Toplam {toplam} alert."))
        self.kuyruk.put(("durum", "Hazır"))

    def _canli_baslat(self):
        if self.canli_aktif:
            self._bilgi_yaz("Canlı izleme zaten çalışıyor.")
            return
        dosya = filedialog.askopenfilename(
            title="İzlenecek log dosyasını seç",
            filetypes=[("Log dosyaları", "*.log"), ("Tüm dosyalar", "*.*")]
        )
        if not dosya:
            return
        self.canli_aktif = True
        self.durum_label.config(text=f"🔴 Canlı: {os.path.basename(dosya)}")
        self._bilgi_yaz(f"Canlı izleme başladı: {dosya}")
        self.canli_thread = threading.Thread(
            target=self._canli_worker, args=(dosya,), daemon=True
        )
        self.canli_thread.start()

    def _canli_worker(self, dosya_yolu: str):
        import time
        ad = os.path.basename(dosya_yolu).lower()
        if "auth" in ad:
            log_turu = "auth"
        elif "access" in ad:
            log_turu = "access"
        elif "ufw" in ad:
            log_turu = "ufw"
        else:
            log_turu = "auth"

        with open(dosya_yolu, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, 2)
            while self.canli_aktif:
                satir = f.readline()
                if satir:
                    log_verisi = log_parcala(satir, log_turu)
                    if log_verisi:
                        alertler = kurallari_uygula(log_verisi, self.kurallar)
                        for alert in alertler:
                            alert_isle(alert)
                            self.kuyruk.put(("alert", alert))
                else:
                    time.sleep(0.5)

    def _canli_durdur(self):
        if self.canli_aktif:
            self.canli_aktif = False
            self.durum_label.config(text="Hazır")
            self._bilgi_yaz("Canlı izleme durduruldu.")

    def _ekrani_temizle(self):
        self.alert_alani.config(state="normal")
        self.alert_alani.delete("1.0", "end")
        self.alert_alani.config(state="disabled")
        self.alert_sayisi = 0
        self.sayac_label.config(text="Toplam Alert: 0")
        self.ip_listesi.delete(0, "end")

    def _kural_editor_ac(self):
        pencere = tk.Toplevel(self.root)
        pencere.title("Kural Editörü")
        pencere.geometry("800x600")
        pencere.configure(bg=RENKLER["bg"])

        tk.Label(
            pencere, text="YAML Kural Editörü",
            font=("Segoe UI", 12, "bold"),
            bg=RENKLER["bg"], fg=RENKLER["baslik"]
        ).pack(anchor="w", padx=15, pady=(15, 5))

        tk.Label(
            pencere,
            text="Kuralları buradan düzenleyebilirsiniz. Kaydet butonuna basınca rules.yaml güncellenir.",
            font=("Segoe UI", 9),
            bg=RENKLER["bg"], fg="#858585"
        ).pack(anchor="w", padx=15, pady=(0, 10))

        editor = scrolledtext.ScrolledText(
            pencere, bg="#1e1e1e", fg="#d4d4d4",
            font=("Consolas", 11), relief="flat",
            insertbackground="white"
        )
        editor.pack(fill="both", expand=True, padx=10)

        try:
            with open("config/rules.yaml", "r", encoding="utf-8") as f:
                editor.insert("1.0", f.read())
        except Exception as e:
            editor.insert("1.0", f"# Dosya okunamadı: {e}")

        alt = tk.Frame(pencere, bg=RENKLER["bg"])
        alt.pack(fill="x", padx=10, pady=10)

        durum = tk.Label(
            alt, text="",
            font=("Segoe UI", 9),
            bg=RENKLER["bg"], fg="#858585"
        )

        def kaydet():
            yeni_icerik = editor.get("1.0", "end")
            try:
                yaml.safe_load(yeni_icerik)
                with open("config/rules.yaml", "w", encoding="utf-8") as f:
                    f.write(yeni_icerik)
                self.kurallar = kurallari_yukle()
                durum.config(text="✅ Kaydedildi. Kurallar yeniden yüklendi.", fg="#4ec94e")
                self._bilgi_yaz("Kural dosyası güncellendi, kurallar yeniden yüklendi.")
            except yaml.YAMLError as e:
                durum.config(text=f"❌ YAML Hatası: {e}", fg="#ff4444")

        def sifirla():
            editor.delete("1.0", "end")
            try:
                with open("config/rules.yaml", "r", encoding="utf-8") as f:
                    editor.insert("1.0", f.read())
                durum.config(text="Dosya yeniden yüklendi.", fg="#858585")
            except Exception as e:
                durum.config(text=f"Hata: {e}", fg="#ff4444")

        tk.Button(
            alt, text="💾  Kaydet", command=kaydet,
            bg="#4ec94e", fg="white",
            font=("Segoe UI", 10), relief="flat",
            padx=15, pady=6, cursor="hand2"
        ).pack(side="left", padx=5)

        tk.Button(
            alt, text="🔄  Sıfırla", command=sifirla,
            bg=RENKLER["buton"], fg="white",
            font=("Segoe UI", 10), relief="flat",
            padx=15, pady=6, cursor="hand2"
        ).pack(side="left", padx=5)

        durum.pack(side="left", padx=15)

    def _kuyruk_kontrol(self):
        try:
            while True:
                tip, veri = self.kuyruk.get_nowait()
                if tip == "alert":
                    self._alert_yaz(veri)
                elif tip == "bilgi":
                    self._bilgi_yaz(veri)
                elif tip == "durum":
                    self.durum_label.config(text=veri)
        except queue.Empty:
            pass
        self.root.after(100, self._kuyruk_kontrol)


def basla():
    root = tk.Tk()
    app = SentinelLogApp(root)
    root.mainloop()


if __name__ == "__main__":
    basla()
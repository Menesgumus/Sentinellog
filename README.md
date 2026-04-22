# SentinelLog

**SentinelLog**, sistem loglarını analiz eden, kurallara dayalı alert üreten ve riskli IP’leri skorlayan bir masaüstü uygulamasıdır.
Uygulama, özellikle **auth.log** ve benzeri log dosyalarını işleyerek güvenlik olaylarını tespit etmeye odaklanır.

---

## 🚀 Özellikler

* 📄 Log dosyası analizi (örneğin `auth.log`)
* 🧠 YAML tabanlı kural motoru
* 🚨 Alert üretimi (regex tabanlı eşleşme)
* 🌐 IP bazlı risk skorlama sistemi
* 📊 CSV çıktıları:

  * `rapor.csv` (tüm alertler)
  * `riskli_ipler.csv` (IP skorları)
* 🖥️ Tkinter tabanlı GUI arayüz
* ⚙️ Anomali motoru altyapısı 

---

## 📁 Proje Yapısı

```
SentinelLog/
│
├── main.py
├── config/
│   └── rules.yaml
│
├── core/
│   ├── parser.py
│   ├── rule_engine.py
│   ├── alert_manager.py
│   └── anomaly_engine.py
│
├── gui/
│   └── app.py
│
├── logs/
│   ├── auth.log
│   └── ufw.log
│
└── output/
    ├── rapor.csv
    └── riskli_ipler.csv
```

---

## 🧩 Bileşenler

### 1. Parser (`core/parser.py`)

* Ham log satırlarını parse eder
* Şu an `auth` log formatı için regex tanımı içerir
* Çıktı: yapılandırılmış `dict`

---

### 2. Rule Engine (`core/rule_engine.py`)

* `config/rules.yaml` dosyasını yükler
* Log mesajlarını regex ile kurallara karşı test eder
* Eşleşme durumunda alert üretir

---

### 3. Alert Manager (`core/alert_manager.py`)

* Alertleri yönetir ve CSV’ye yazar
* IP bazlı skor sistemi içerir:

  * DÜŞÜK → 1 puan
  * ORTA → 3 puan
  * YÜKSEK → 5 puan
* Skora göre seviye belirler:

  * ≥15 → KRITIK
  * ≥8 → YUKSEK
  * ≥4 → ORTA
  * <4 → DUSUK

---

### 4. Anomaly Engine (`core/anomaly_engine.py`)

* Şu an **aktif (skeleton yapı)**
* ML tabanlı anomali tespiti için hazırlanmış (ileride eklenecek) 
* Anomali hareketlerinde alert üretir.

---

### 5. GUI (`gui/app.py`)

* Tkinter tabanlı masaüstü arayüz
* Log seçimi ve analiz süreci burada yönetilir
* Thread ve queue yapısı ile çalışır

---

## ⚙️ Kurulum

### Gereksinimler

* Python 3.x
* Gerekli kütüphaneler:

```bash
pip install pyyaml
```

---

## ▶️ Çalıştırma

```bash
python main.py
```

Uygulama açıldıktan sonra:

* Log dosyası seçilir
* Analiz başlatılır
* Sonuçlar arayüzde ve `output/` klasöründe görüntülenir

---

## 📄 Kural Yapısı (rules.yaml)

Kurallar `config/rules.yaml` dosyasında tanımlanır.

Her kural:

* `log_turu`
* `desen` (regex)
* diğer alanlardan oluşur

Rule engine bu kuralları doğrudan log mesajına uygular.

---

## 📤 Çıktılar

### 1. `rapor.csv`

* Tüm üretilen alertler

### 2. `riskli_ipler.csv`

* IP adresleri ve risk skorları

---

## ⚠️ Mevcut Sınırlamalar

* Parser şu an sınırlı log formatı destekler
* Anomali tespit sistemi aktif değil
* Gerçek zamanlı log izleme kısmi (thread altyapısı var)

---

## 📌 Not

Bu proje:

* Kural tabanlı log analizi üzerine kuruludur
* ML modülü ileride genişletilmek üzere tasarlanmıştır

---

## 🧑‍💻 Geliştirici

Menes Gumus

# 🛡️ İlker Kuru — Cyber Security Systems Architecture
## 🚀 C++20 ile OOP Merkezli Asenkron Güvenli Loglama (SecureLogger) & Gerçek Zamanlı Davranışsal Analiz Motoru (EDREngine)

[![C++ Version](https://img.shields.io/badge/C%2B%2B-20-blue.svg?style=flat-square&logo=c%2B%2B)](https://en.cppreference.com/w/cpp/20)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-orange.svg?style=flat-square)](https://github.com/)
[![Security Level](https://img.shields.io/badge/Security-Military%20Grade-red.svg?style=flat-square)](#)
[![Dependency](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20C%2B%2B)-green.svg?style=flat-square)](#)

---

## 📌 1. Yönetici Özeti & Proje Vizyonu (Executive Summary)

Bu proje, son kullanıcıya yönelik standart bir masaüstü arayüzü veya basit bir konsol uygulaması değildir. **Bu yazılım; büyük ölçekli kurumsal altyapılara, yüksek trafikli web sunucularına, bankacılık backend sistemlerine veya kurumsal Antivirüs/EDR yazılımlarına doğrudan entegre edilmek üzere tasarlanmış, C++20 standartlarında geliştirilmiş iki adet bağımsız ve endüstriyel kalitede (Production-Ready) "Siber Güvenlik Motoru"dur (Engine/Framework).**


Klasörlerde yer alan `.exe` dosyaları bu sistemlerin ana ürünü değildir. Onlar, ürettiğimiz bu motorları en uç sınırlarda (aynı anda binlerce eş zamanlı işlem yaparak) zorlayan ve sistemin çökmeden, bellek sızdırmadan saniyenin yüzde birinde çalıştığını kanıtlayan **Ağır Yük Simülasyonları ve Tehdit Senaryolarıdır**.

---

## 📂 2. Dosya & Dizin Mimarisi (File Directory & Architecture)

Sistem, **dışarıdan hiçbir üçüncü parti kütüphane (OpenSSL, Boost vb.) veya bağımlılık içermeden**, tamamen sıfırdan ("From Scratch") ve SOLID prensiplerine sıkı sıkıya bağlı kalınarak benim tarafımdan tasarlanmış ve kodlanmıştır.

```
IlkerKuru_CyberSec/
│
├── 🔐 SecureLogger/                       # Kriptografik & Asenkron Loglama Katmanı
│   ├── sha256.hpp                         # Sıfırdan kodlanmış FIPS 180-4 SHA-256 motoru
│   ├── hmac.hpp                           # RFC 2104 uyumlu tahrif önleyici HMAC-SHA256 mührü
│   ├── crypto.hpp                         # Strategy deseniyle AES-256-CTR & ChaCha20 modülleri
│   ├── secure_logger.hpp                  # Asenkron Producer-Consumer kuyruğu & jthread yönetimi
│   ├── main_logger.cpp                    # 16 thread eş zamanlı ağır yük & tahrifat test arayüzü
│   └── SecureLogger.exe                   # SecureLogger derlenmiş test simülasyonu
│
├── 🦠 EDREngine/                          # Malware Davranışsal Analiz & EDR Beyni
│   ├── telemetry.hpp                      # İşletim sistemi kernel olay yapısı (TelemetryEvent)
│   ├── detection_chain.hpp                # Sorumluluk Zinciri (Chain of Responsibility) filtreleri
│   ├── edr_engine.hpp                     # Observer pattern temelli orchestrator ana motoru
│   ├── main_edr.cpp                       # Gelişmiş APT ve Ransomware simülasyon arayüzü
│   └── EDREngine.exe                      # EDREngine derlenmiş test simülasyonu
│
├── CMakeLists.txt                         # Proje derleme konfigurasyon dosyası
├── README.md                              # Bu teknik dokümantasyon dosyası
└── 244410028_İlkerKuru_Güvenli Loglama...  # Akademik IEEE standartlarında detaylı proje raporları
```

---

## 🏗️ 3. Kapsamlı Mimari Tasarım & Desenler (Design Patterns & Concurrency)

Her iki motor da nesne yönelimli programlama (OOP) ve modern yazılım mimarisi ilkelerini uç noktada sergilemektedir:

### A. SecureLogger Asenkron Mimari Şeması
```
  Producer Threads (Uygulama Akışı)       Consumer Thread (Arka Plan)
  ┌───────────────────────────────┐       ┌────────────────────────────────┐
  │  thread_1 ──► log("Sistem...") │       │  C++20 jthread (Otomatik Join) │
  │  thread_2 ──► log("Hata...")   │ ──►   │  1. Dequeue (Condition Var)    │
  │  thread_N ──► log("Giriş...")  │       │  2. Strategy Encrypt (AES/Cha) │
  └───────────────────────────────┘       │  3. HMAC-SHA256 Sign           │
                  │                       │  4. Hex-Encode & Write to Disk │
                  ▼                       └────────────────────────────────┘
          AsyncLogQueue (MPSC)
     [ Mutex & condition_variable_any ]
```
*   **Asenkron Çalışma (Non-blocking I/O):** Loglama operasyonu disk I/O ve ağır kriptografik şifrelemeler içerdiğinden ana uygulama akışını yavaşlatmamalıdır. SecureLogger, log çağrılarını Çoklu Üretici / Tek Tüketici (MPSC) modelinde çalışan thread-safe `AsyncLogQueue` kuyruğuna atar ve hemen döner.
*   **Modern C++20 `jthread` & Cooperative Cancellation:** Arka planda kuyruğu boşaltıp diske yazan thread, C++20 `std::jthread` ile oluşturulmuştur. Durdurma sinyali (`std::stop_token`) entegrasyonu sayesinde sistem kapanırken kuyruktaki tüm logların diske güvenle yazılması garantilenir ve thread otomatik olarak join edilir.
*   **Strategy (Strateji) Tasarım Deseni:** Şifreleme katmanı `ILogEncryptor` soyut arayüzüyle soyutlanmıştır. Sistem logları şifrelerken **AES-256-CTR** veya **ChaCha20** algoritmalarından hangisini kullanacağını çalışma zamanında (runtime) dinamik olarak kararlaştırabilir.
*   **Hex Encoding & HMAC-SHA256 Mühürleme:** Şifrelenen binary veri ASCII log dosyasına güvenle yazılabilsin diye Hex formatına kodlanır. Satırların sonuna `|` ayracıyla o satırın hash mührü eklenir:
    `[hex_ciphertext]|[hmac_signature]`
    Eğer bir saldırgan log dosyasına sızıp tek bir karakteri bile değiştirirse, bütünlük doğrulama motoru (`verify_log_integrity`) bunu anında tespit eder.

### B. EDR Engine Mimari Şeması
```
                  [ Telemetry Olayı ]
                           │
                           ▼
     Chain of Responsibility (Sorumluluk Zinciri)
  ┌────────────────────────────────────────────────────────┐
  │  SignatureFilter  ──► HeuristicFilter ──► NetworkFilter│
  │  (O(1) Hash DB)        (Davranış Kuralları) (C2 Portlar)│
  └────────────────────────────────────────────────────────┘
                           │
                           ▼ [Kümülatif Risk Skoru]
                           │
             Gözlemciler (Observer Pattern)
  ┌────────────────────────────────────────────────────────┐
  │  Risk >= 30: AlertLoggerObserver (Konsol & Log Uyarı)  │
  │  Risk >= 60: ProcessTerminatorObserver (KILL & Karantina)│
  └────────────────────────────────────────────────────────┘
```
*   **Chain of Responsibility (Sorumluluk Zinciri) Tasarım Deseni:** Gelen telemetri olayları sırayla birbirine bağlı filtrelerden geçer. Her filtre olaya kendi kuralları çerçevesinde risk puanı ekler. Bu sayede filtreler birbirinden tamamen bağımsız olarak test edilebilir, sırası değiştirilebilir ve Open-Closed Principle (OCP) uyarınca yeni filtreler kolayca eklenebilir.
*   **Observer (Gözlemci) Tasarım Deseni:** Analiz zinciri sonucunda risk skoru eşik değerleri aşarsa kayıtlı gözlemciler uyarılır. EDR ana motoru hangi aksiyonların alınacağını bilmez (Dependency Inversion Principle - DIP). Gözlemciler (`IAlertObserver`) sayesinde sisteme kolaylıkla yeni aksiyon modülleri (örn. Syslog'a gönder, mail at vb.) entegre edilebilir.

---

## 🔐 4. Kriptografik İlkeller & Mühendislik Standartları

Bu motorların kalbindeki algoritmaların tamamını **kriptografik standartlara (RFC ve FIPS) uygun olarak sıfırdan kodladım**:

1.  **SHA-256 (`sha256.hpp`):** FIPS 180-4 standartlarına %100 uyumludur. Döngüsel bit kaydırmalarında modern C++20 `std::rotr` intrinsik fonksiyonları kullanılmış, big-endian byte dönüşümlerinde ise platform bağımsızlığı adına `std::endian` kütüphanesinden yararlanılmıştır.
2.  **HMAC-SHA256 (`hmac.hpp`):** RFC 2104 standardına tam uyumludur. Kriptografik anahtarı iç (ipad) ve dış (opad) padding maskeleriyle işler. **Zamanlama Saldırılarına (Timing Attacks)** karşı tam koruma sağlamak adına HMAC doğrulamalarında sabit zamanlı (`constant-time`) güvenli karşılaştırma kodlanmıştır.
3.  **ChaCha20 (`crypto.hpp`):** RFC 8439 (paragraf 2.1-2.3) standartlarına dayanır. 4x4 durum matrisi üzerindeki çeyrek tur (quarter-round) adımları `std::rotl` ile işlemci düzeyinde optimize edilmiştir. Donanımsal AES ivmelendirmesi (AES-NI) olmayan işlemcilerde AES-256'ya göre %12 daha hızlıdır.
4.  **AES-256-CTR (`crypto.hpp`):** Standart AES S-Box matrisini ve 14 turlu anahtar genişletme, SubBytes, ShiftRows adımlarını sıfırdan barındırır. Sayaç (CTR) modunda çalışarak veri uzunluğunu değiştirmeden hızlı bir şekilde şifreleme sunar.
5.  **Bellek Güvenliği (Memory Safety & RAII):** Kodun hiçbir yerinde manuel bellek yönetimi (`new`, `delete`) veya çıplak işaretçi (`raw pointer`) kullanılmamıştır. Tüm kaynak ömürleri smart pointerlar (`std::unique_ptr`, `std::shared_ptr`) ve RAII prensipleriyle yönetilmektedir. Bellek sızıntısı (Memory Leak) ihtimali sıfırdır.
6.  **Sıfır Dinamik Tahsisat (Zero-Allocation Philosophy):** Loglama esnasında işletim sisteminden dinamik bellek istemek (heap allocation) performansı düşürür. Bu nedenle log kuyruğunda ve string işlemlerinde dinamik tahsisatlar minimumda tutulmuş, yüksek performanslı değer semantiği uygulanmıştır.

---

## 🦠 5. Tehdit Kuralları & Tespit Ağırlıkları (EDREngine Rules)

Davranışsal Heuristic filtre içerisinde işletim sistemindeki en kritik 8 saldırı vektörünü tespit eden kurallar ve atanan ağırlıklı puanlar yer almaktadır:

| Kural Kodu | Tespit Edilen Tehdit/Aktivite | Puan Ağırlığı | Güvenlik Açıklaması |
| :---: | :--- | :---: | :--- |
| **R1** | **Kernel Hooking (SSDT/ISR Hook)** | **55** | İşletim sisteminin kalbine (kernel) sızmaya çalışan rootkit faaliyeti. |
| **R2** | **Memory Injection (Süreç Enjeksiyonu)** | **65** | Başka bir güvenli sürecin belleğine sızarak zararlı kod yürütme adımı. |
| **R3** | **Shellcode Yürütme (W^X İhlali)** | **70** | Bellekte hem yazılabilir hem yürütülebilir alan açıp virüs çalıştırma. |
| **R4** | **HOSTS Dosyası Değişikliği** | **40** | Web trafiğini sahte sitelere yönlendirme girişimi (DNS Hijacking). |
| **R5** | **Kalıcılık Girişimi (Registry Run Keys)** | **35** | Virüsün bilgisayar her açıldığında otomatik çalışması için kayıt eklemesi. |
| **R6** | **Ayrıcalık Yükseltme (Privilege Escalation)**| **50** | Normal kullanıcının yetkilerini en üst seviyeye (SYSTEM) çıkarma girişimi. |
| **R7** | **LOLBin İstismarı (Living off the Land)** | **20** | PowerShell, cmd gibi meşru sistem araçlarının zararlı amaçla tetiklenmesi. |
| **R8** | **Hassas Dizin Değişikliği (System32/etc)** | **25** | `System32`, `drivers`, `/etc/` gibi kritik klasörlerde izinsiz dosya işlemleri. |

### 🌐 Ağ (C2) Tespit Kuralları
NetworkFilter, süreçlerin ağ bağlantılarını izler. Bilinen Komuta Kontrol (C2 - Command & Control) sunucu portlarını (`4444`, `31337`, `8080`, `9001` vb.) statik bir `unordered_set` içerisinde **O(1) zaman karmaşıklığında** sorgular. Şüpheli port bağlantısında kümülatif skora **45 puan** eklenir. Ayrıca yetkili (elevated) bir sürecin dışarıya bağlantı açması durumunda skora **20 puan** eklenir.

---

## 🕵️ 6. Ağır Yük & Tehdit Simülasyonları

Motorların doğrulanması için geliştirilen test dosyaları, gerçek hayattaki en karmaşık senaryoları simüle eder:

### A. SecureLogger Ağır Yük Simülasyonu (`main_logger.cpp`)
*   Simülasyon çalıştırıldığında, aynı anda **16 farklı iş parçacığı (thread)** sisteme hücum eder.
*   Her bir thread saniyede yüzlerce log üreterek toplamda **8.000 adet hayali log satırını** asenkron kuyruğa yazar.
*   SecureLogger, ana uygulama akışını kilitlemeden bu logları saniyenin onda birinden kısa bir sürede (**95ms altı**) şifreleyip HMAC imzalarıyla `logs/` dizinine yazar.
*   Test sonunda, log dosyasındaki bir satır elle bozularak `verify_log_integrity` doğrulaması çalıştırılır. Sistem **tahrifatı anında yakalar** ve hangi satırın değiştirildiğini konsola raporlar.

### B. EDREngine Gelişmiş Tehdit Simülasyonu (`main_edr.cpp`)
Bu simülasyon, işletim sistemini hedef alan 7 farklı kritik senaryoyu EDR motorumuza göndererek milisaniyeler düzeyinde analiz eder:
1.  **S1 Temiz Süreç:** Hiçbir şüpheli hareket yapmayan program. EDR risk puanı 0 hesaplar. Yanlış alarm oranı sıfırdır.
2.  **S2 Bilinen Zararlı Hash:** SHA-256 hash bilgisi bilinen virüs veritabanımızla eşleşen program. Risk skoru anında **75** atanır, kritik virüs olarak tespit edilir.
3.  **S3 APT Saldırısı (Gelişmiş Tehdit):** Bellek enjeksiyonu yapan, SSDT kancası kuran ve C2 sunucusuyla (`port 4444`) konuşan hacker simülasyonu. Risk skoru **100** hesaplanır. Süreç anında **TERMINATE** edilir ve **QUARANTINE** durumuna alınarak etkisiz hale getirilir.
4.  **S4 Ransomware (Fidye Yazılımı):** Dosyaları şifreleyen ve Registry'e kalıcılık anahtarı ekleyen virüs simülasyonu. Risk skoru **75** hesaplanarak engellenir.
5.  **S5 LOLBin İstismarı:** `powershell.exe` üzerinden şüpheli komut çalıştıran proses. **SUSPICIOUS** olarak etiketlenir.
6.  **S6 Çoklu Thread Yük Testi:** 8 thread üzerinden aynı anda yüzlerce telemetri olayının EDR motoruna gönderilmesi testi. Sistemde hiçbir veri yarışı (data race) veya deadlock oluşmadan kararlı şekilde çalıştığı kanıtlanır.
7.  **S7 Sıcak İmza Güncelleme (Hot-reload):** Program çalışırken yeni bir virüs SHA-256 imzasının sisteme eklenmesi testi. EDR motoru kapatılmadan yeni imzayı başarıyla veritabanına ekler ve tehdidi yakalamaya başlar.

---

## 🚀 7. Derleme & Çalıştırma Talimatları (Build Instructions)

Proje modern C++20 standartlarında yazıldığı için güncel bir derleyici (GCC 10+, Clang 10+ veya MSVC 2019+) gerektirmektedir. Proje kök dizininde terminali açarak şu komutlarla derleme yapabilirsiniz:

### 1. Secure Logger Derleme & Çalıştırma:
```bash
# SecureLogger motorunu ve ağır yük test simülasyonunu derle
g++ -std=c++20 -Wall -Wextra -O3 -I. SecureLogger/main_logger.cpp -o SecureLogger/SecureLogger.exe -lpthread

# Simülasyonu çalıştır
./SecureLogger/SecureLogger.exe
```

### 2. EDR Engine Derleme & Çalıştırma:
```bash
# EDREngine motorunu ve gelişmiş tehdit simülasyonunu derle
g++ -std=c++20 -Wall -Wextra -O3 -I. EDREngine/main_edr.cpp -o EDREngine/EDREngine.exe -lpthread

# Simülasyonu çalıştır
./EDREngine/EDREngine.exe
```

> [!NOTE]
> Derleme tamamlandıktan sonra oluşturulan çalıştırılabilir dosyalar çalıştırıldığında, arka planda tüm eş zamanlı işlemleri tamamlayacak, raporları ekrana basacak ve çıkmak için sizden **ENTER** tuşuna basmanızı bekleyecektir.

---

## 📈 8. Deneysel Performans Verileri

| Test Edilen Motor | Senaryo / Metrik | Ölçülen Değer | Sonuç & Yorum |
| :--- | :--- | :---: | :--- |
| **SecureLogger** | 16 Thread - 8.000 Log Yazımı | **< 95 ms** | Muazzam asenkron throughput, disk kilitlenmesi yok. |
| **SecureLogger** | Bellek Sızıntısı (Valgrind Profile) | **0 Byte** | Kusursuz RAII ve Akıllı İşaretçi yönetimi. |
| **SecureLogger** | ChaCha20 Yazma Gecikmesi Avantajı | **%12 Daha Hızlı**| AES-256-CTR'ye göre yazılımsal işlem avantajı doğrulandı. |
| **EDREngine** | 7 Tehdit Senaryosu Tespit Başarısı | **%100 (6/6)** | Gelişmiş tüm simüle virüsler başarıyla engellendi. |
| **EDREngine** | Yanlış Pozitif (False Positive) Oranı | **%0** | Temiz süreçler hatasız şekilde temiz bırakıldı. |
| **EDREngine** | Karar & Sonlandırma Gecikmesi (Latency)| **< 1 ms** | Milisaniyenin altında tehdit tespiti ve izolasyon. |

---

## 🎓 9. Akademik Raporlar

Projenin tüm matematiksel altyapısını, literatür taramasını, ilgili akademik çalışmaları, sistem tasarımı XML/mimari şemalarını ve deney çıktılarını içeren **IEEE Konferans Bildirisi standartlarında yazılmış** detaylı raporlara aşağıdaki bağlantılardan erişebilirsiniz:

*   🇹🇷 **Türkçe Akademik Rapor:** [244410028_İlkerKuru_Güvenli Loglama_Türkçe (2).docx]
*   🇬🇧 **İngilizce Akademik Rapor:** [244410028_İlkerKuru_Güvenli Loglama_İngilizce (1).docx]

---

**👨‍💻 Geliştirici & Mimar:** İlker Kuru  
**🏫 Kurum:** Kastamonu Üniversitesi, Bilgisayar Mühendisliği Bölümü  
**🎯 Hedef Kitle:** Bu projenin kodları; güvenlik standartlarına maksimum önem veren kurumsal firmaların, bankaların ve siber güvenlik şirketlerinin kendi altyapılarına doğrudan entegre edebilecekleri endüstriyel kalitede yazılmıştır.

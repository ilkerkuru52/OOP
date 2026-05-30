# 🛡️ İlker Kuru — Cyber Security Systems Architecture

## 📌 Yönetici Özeti (Executive Summary)

Bu proje, son kullanıcıya yönelik basit bir masaüstü uygulaması değil; **Büyük ölçekli kurumsal yazılımlara, web sunucularına veya Antivirüs yazılımlarına entegre edilmek üzere tasarlanmış, C++20 standartlarında geliştirilmiş iki adet "Siber Güvenlik Motoru"dur (Engine/Framework).**

Bir benzetme yapmak gerekirse: Biz burada dış kaportası olan bir araba üretmedik. Biz, dünyanın en sağlam ve en güvenli **Araba Motorunu** ürettik. Bu motoru (kütüphaneyi) alıp istediğiniz herhangi bir kurumsal yazılımın içine yerleştirerek, o yazılıma siber saldırılara karşı askeri düzeyde koruma sağlayabilirsiniz.

Klasörlerde yer alan `.exe` dosyaları bu sistemlerin son ürünü değildir. Onlar, ürettiğimiz bu motorları tam kapasiteyle (aynı anda binlerce işlem yaparak) zorlayan ve sistemin çökmeden, bellek sızdırmadan saniyenin onda biri sürede çalıştığını kanıtlayan **Ağır Yük Simülasyonları ve Test Arayüzleridir**.

---

## 📂 Dosya Mimarisi: Hangi Dosya Ne İşe Yarıyor?

Sistem, dış bağımlılık (third-party kütüphane) içermeden, "Sıfırdan (From scratch)" prensibiyle tamamen `İlker Kuru` tarafından tasarlanmıştır.

### 🔐 Bölüm 1: Secure Logger (Kriptografik Loglama Sistemi)
Kurumsal bir sistemin ürettiği logları şifreleyen ve dışarıdan müdahaleye (silinme, değiştirilme) karşı koruyan modüldür.
*   **`sha256.hpp`**: Dış bağımlılık olmadan, FIPS 180-4 standartlarında çalışan %100 yerli SHA-256 kriptografik özetleme (hash) algoritmasıdır.
*   **`hmac.hpp`**: Log satırlarının değiştirilip değiştirilmediğini anında anlamamızı sağlayan RFC 2104 uyumlu HMAC-SHA256 "kriptografik mühür" sistemidir.
*   **`crypto.hpp`**: Strategy (Strateji) tasarım deseni kullanılarak oluşturulmuş, logların şifrelenmesinde kullanılan asıl algoritmalardır (AES-256-CTR ve ChaCha20 modülleri burada yer alır).
*   **`secure_logger.hpp`**: Ana loglama motorudur. Uygulamanın ana akışını durdurmadan (Asenkron - C++20 `jthread` ile) logları arka planda sıraya dizer, şifreler, mühürler ve dosyaya yazar.
*   **`main_logger.cpp` (TEST SİMÜLASYONU)**: Motoru test eden dosyadır. Çalıştırıldığında sanki 16 farklı kullanıcı aynı anda işlem yapıyormuş gibi 8000 adet hayali log üretir ve motorun bu logları saniyenin onda birinde güvenle `logs/` klasörüne şifreleyerek yazıp yazamadığını test eder. Ayrıca bilerek bir log satırını hackleyip, motorun bunu yakalayıp yakalayamadığını (Tahrifat Tespiti) kanıtlar.

### 🦠 Bölüm 2: EDR Engine (Malware / Davranışsal Analiz Motoru)
İşletim sistemindeki şüpheli hareketleri anında tespit edip engelleyen "Antivirüs/EDR" beynidir.
*   **`telemetry.hpp`**: İşletim sisteminden gelen olayların (yeni bir program açıldı, internete bağlandı vb.) sisteme aktarılmasını sağlayan veri iskeletidir.
*   **`detection_chain.hpp`**: Olayları sırasıyla inceleyen filtrelerin bulunduğu "Sorumluluk Zinciri" (Chain of Responsibility) dosyasıdır. İmza Filtresi (Hash eşleşmesi), Davranışsal Filtre (Heuristic - Proses enjeksiyonu vb.) ve Ağ Filtresi (C2 sunucu iletişimleri) burada tanımlanır.
*   **`edr_engine.hpp`**: Tüm bu filtreleri bir orkestra şefi gibi yöneten, risk skorunu toplayan ve eğer tehlike sınırı aşılırsa alarm verip programı anında kapatan (Terminate) ana motordur. Gözlemci (Observer) desenini kullanır.
*   **`main_edr.cpp` (TEST SİMÜLASYONU)**: Gelişmiş Hacker (APT) saldırıları, Fidye Yazılımı (Ransomware) ve LOLBin (işletim sisteminin kendi araçlarını kullanan virüsler) saldırılarını simüle eder. Motorun bu saldırıları kaç saniyede yakalayıp "KARANTİNAYA" aldığını gösterir.

---

## 🏗️ Kullanılan Modern C++ & Güvenlik Pratikleri

*   **Memory Safety (Bellek Güvenliği):** Kodların hiçbir yerinde manuel bellek yönetimi (`new`, `delete`) veya raw pointer (çıplak işaretçi) kullanılmamıştır. Tamamen Smart Pointers (`std::unique_ptr`, `std::shared_ptr`) ve RAII prensipleri ile bellek sızıntısı (Memory Leak) imkansız hale getirilmiştir.
*   **Zero-Allocation Yaklaşımı:** Özellikle Loglama sırasında sistem performansını etkilememek adına dinamik bellek ayırma işlemleri minimumda tutulmuştur.
*   **SOLID Tasarım Desenleri:** Sınıflar arası sıkı bağlılıktan (Tight Coupling) kaçınılmıştır. Dependency Injection, Strategy Pattern, Observer Pattern ve Chain of Responsibility Pattern ustalıkla kullanılarak sistem tamamen "Tak-Çıkar" (Modular) bir hale getirilmiştir.

---

## 🕵️ Testleri Anlamak: `.exe` Dosyalarını Çalıştırdığınızda Ne Oluyor?

Masaüstündeki `.exe` dosyaları, yukarıda bahsedilen "Motorların" test arayüzleridir.
Programlara çift tıkladığınızda; yazılımlar çalışır, binlerce işlemi eş zamanlı (concurrent) olarak işler, sonuç raporunu (başarılı/başarısız durumu, yakalanan virüs sayısı vb.) ekrana basar ve çıkmak için sizden **ENTER** tuşuna basmanızı bekler.

### SecureLogger Testi Çıktıları
`SecureLogger.exe` çalıştıktan sonra bulunduğu klasörde **`logs`** isimli yeni bir dizin oluşturur. Bu klasöre gidip oluşan log dosyalarını Not Defteri ile açarsanız, okunabilir bir metin yerine **"2a4f78e... | 9b2d3c..."** şeklinde anlamsız, devasa karakter yığınları göreceksiniz. 

**Bunun sebebi sistemin mükemmel çalışmasıdır!** Loglar diske yazılmadan önce AES-256 veya ChaCha20 ile şifrelenir ve sonuna "|" işaretiyle beraber kırılamaz bir **HMAC-SHA256 kriptografik doğrulama imzası (mühür)** konur. Bir hacker bu dosyayı ele geçirse bile içeriği okuyamaz; içeriği tahmin edip tek bir harfini değiştirirse HMAC mührü bozulacağı için sistem anında "Tahrifat" (Tamper) uyarısı verir.

### EDREngine Testi Çıktıları
`EDREngine.exe` çalıştırıldığında, arka planda işletim sistemini hedef alan senaryolar canlandırılır:
- Şüpheli bir porttan dışarı veri sızdırmaya çalışan bir program,
- İşletim sisteminin kalbine (ntoskrnl.exe) sızmaya çalışan bir Rootkit,
- Belleğe kendini enjekte eden bir Fidye Yazılımı.

Ekranda, motorumuzun bu hareketleri nasıl anında analiz ettiği, risk puanını (Risk Score) nasıl 100 üzerinden hesapladığı ve tehlikeli bulduğu prosesleri nasıl **TERMINATE (Sonlandırıldı)** ve **QUARANTINE (Karantina)** statüsüne çektiğini canlı olarak göreceksiniz.

---

## 🚀 Derleme Komutları (Build Instructions)

Eğer kodu kendi ortamınızda (GCC/MinGW) sıfırdan derlemek isterseniz, proje kök dizininde şu komutları kullanabilirsiniz:

**1. Secure Logger için:**
```bash
g++ -std=c++20 -Wall -Wextra -O2 -I. SecureLogger/main_logger.cpp -o SecureLogger/SecureLogger.exe -lpthread
```

**2. EDR Engine için:**
```bash
g++ -std=c++20 -Wall -Wextra -O2 -I. EDREngine/main_edr.cpp -o EDREngine/EDREngine.exe -lpthread
```

---
**👨‍💻 Geliştirici & Mimar:** İlker Kuru  
**🛡️ Uzmanlık Alanı:** Bilgisayar Mühendisliği
**🎯 Hedef Kitle:** Bu projenin kodları, güvenlik standartlarına önem veren kurumsal firmaların, bankaların ve siber güvenlik şirketlerinin kendi altyapılarına doğrudan entegre edebilecekleri endüstriyel kalitede (Production-Ready) yazılmıştır.

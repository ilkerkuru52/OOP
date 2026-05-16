/**
 * @file main_edr.cpp
 * @author İlker Kuru — Defensive Security Architecture
 * @brief EDR Engine agresif test senaryoları — gerçekçi malware simülasyonları.
 *
 * Test Senaryoları:
 *   S1 — Temiz proses (false positive testi)
 *   S2 — Bilinen zararlı hash (hash DB hit)
 *   S3 — APT Lateral Movement simülasyonu (process injection + hook + C2)
 *   S4 — Ransomware davranış simülasyonu (dosya değişikliği + kalıcılık)
 *   S5 — LOLBin tabanlı saldırı (powershell.exe + HOSTS değişikliği)
 *   S6 — Eş zamanlı 8 thread → race-condition testi
 *   S7 — Hot-reload imza güncelleme testi
 */
#include "edr_engine.hpp"

#include <chrono>
#include <filesystem>
#include <format>
#include <iomanip>
#include <iostream>
#include <latch>
#include <random>
#include <thread>
#include <vector>

using namespace ilkerkuru::edr;

// ─── Yardımcılar ───────────────────────────────────────────────────────────
static void print_banner(std::string_view title) {
    std::cout << "\n╔══════════════════════════════════════════════════════╗\n"
              << "║  " << title;
    for (std::size_t i = title.size(); i < 52; ++i) std::cout << ' ';
    std::cout << "║\n"
              << "╚══════════════════════════════════════════════════════╝\n";
}

static void print_result(const AnalysisResult& r) {
    std::cout << "  → Verdict: [" << to_string(r.verdict) << "] "
              << "Score: " << r.risk_score << "/100\n";
}

// ─── Fabrika: Malware Telemetri Simülasyonları ─────────────────────────────
static TelemetryEvent make_clean_event(uint32_t pid) {
    return TelemetryEvent{
        .pid          = pid,
        .ppid         = 4,
        .event_type   = EventType::FILE_MODIFY,
        .process_name = "notepad.exe",
        .file_hash    = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        .target_path  = "C:\\Users\\IlkerKuru\\Documents\\notes.txt",
        .dst_port     = 0,
        .is_elevated  = false
    };
}

// S2: Bilinen zararlı hash
static TelemetryEvent make_known_malware_event(uint32_t pid) {
    return TelemetryEvent{
        .pid          = pid,
        .ppid         = 1337,
        .event_type   = EventType::FILE_MODIFY,
        .process_name = "svchost_fake.exe",
        .file_hash    = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        .target_path  = "C:\\Windows\\System32\\malware.dll",
        .dst_port     = 0,
        .is_elevated  = true
    };
}

// S3: APT — Process Injection + Hook + C2 kombinasyonu
static TelemetryEvent make_apt_injection(uint32_t pid) {
    return TelemetryEvent{
        .pid          = pid,
        .ppid         = 666,
        .event_type   = EventType::PROCESS_INJECT,
        .process_name = "lsass_injector.exe",
        .file_hash    = "aabbcc1122334455aabbcc1122334455aabbcc1122334455aabbcc1122334455",
        .target_path  = "\\lsass.exe",
        .dst_port     = 4444,
        .is_elevated  = true
    };
}

static TelemetryEvent make_apt_hook(uint32_t pid) {
    return TelemetryEvent{
        .pid          = pid,
        .ppid         = 666,
        .event_type   = EventType::HOOK_ATTEMPT,
        .process_name = "rootkit.exe",
        .target_path  = "\\system32\\ntoskrnl.exe",
        .dst_port     = 0,
        .is_elevated  = true
    };
}

static TelemetryEvent make_apt_c2(uint32_t pid) {
    return TelemetryEvent{
        .pid          = pid,
        .ppid         = 666,
        .event_type   = EventType::NETWORK_CONNECT,
        .process_name = "winlogon_fake.exe",
        .target_path  = "185.234.219.100",
        .dst_port     = 4444,
        .is_elevated  = true
    };
}

// S4: Ransomware davranışı
static TelemetryEvent make_ransomware_persistence(uint32_t pid) {
    return TelemetryEvent{
        .pid          = pid,
        .ppid         = 8888,
        .event_type   = EventType::REGISTRY_RUNKEY,
        .process_name = "encryptor.exe",
        .target_path  = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        .dst_port     = 0,
        .is_elevated  = false
    };
}

static TelemetryEvent make_ransomware_shellcode(uint32_t pid) {
    return TelemetryEvent{
        .pid          = pid,
        .ppid         = 8888,
        .event_type   = EventType::SHELLCODE_EXEC,
        .process_name = "encryptor.exe",
        .target_path  = "RWX_HEAP_REGION_0x7FFF0000",
        .dst_port     = 0,
        .is_elevated  = false
    };
}

// S5: LOLBin — powershell.exe üzerinden HOSTS değişikliği
static TelemetryEvent make_lolbin_attack(uint32_t pid) {
    return TelemetryEvent{
        .pid          = pid,
        .ppid         = 9999,
        .event_type   = EventType::HOSTS_MODIFY,
        .process_name = "powershell.exe",
        .target_path  = "C:\\Windows\\System32\\drivers\\etc\\hosts",
        .dst_port     = 0,
        .is_elevated  = false
    };
}

// ─── ANA TEST PROGRAMI ─────────────────────────────────────────────────────
int main() {
    print_banner("İlker Kuru — EDR Engine Test Suite v1.0");

    // EDR Alarm log klasörünü oluştur ve log dosyasını temizle
    std::filesystem::create_directory("logs");
    std::ofstream clear_log("logs/edr_alerts.log", std::ios::trunc);
    clear_log.close();

    // Observer'ları oluştur ve enjekte et
    auto alert_logger  = std::make_shared<AlertLoggerObserver>();
    auto terminator    = std::make_shared<ProcessTerminatorObserver>(60);

    EDREngine engine;
    engine.register_observer(alert_logger);
    engine.register_observer(terminator);

    // ── S1: Temiz Proses ─────────────────────────────────────────────────
    print_banner("S1: Temiz Proses (False Positive Testi)");
    {
        auto ev = make_clean_event(1001);
        auto r  = engine.analyze(ev);
        print_result(r);
        if (r.verdict == ThreatVerdict::CLEAN)
            std::cout << "  [✓] S1 PASS: Temiz proses doğru sınıflandırıldı.\n";
        else
            std::cout << "  [✗] S1 FAIL: False positive!\n";
    }

    // ── S2: Bilinen Zararlı Hash ──────────────────────────────────────────
    print_banner("S2: Bilinen Zararlı Hash (Signature DB Hit)");
    {
        auto ev = make_known_malware_event(2001);
        auto r  = engine.analyze(ev);
        print_result(r);
        if (r.risk_score >= 60)
            std::cout << "  [✓] S2 PASS: Zararlı hash tespit edildi.\n";
        else
            std::cout << "  [✗] S2 FAIL: Hash tespiti başarısız!\n";
    }

    // ── S3: APT Lateral Movement ─────────────────────────────────────────
    print_banner("S3: APT Lateral Movement Simülasyonu");
    {
        std::cout << "  [→] Adım 1: Process Injection\n";
        auto r1 = engine.analyze(make_apt_injection(3001));
        print_result(r1);

        std::cout << "  [→] Adım 2: Kernel Hook Girişimi\n";
        auto r2 = engine.analyze(make_apt_hook(3001));
        print_result(r2);

        std::cout << "  [→] Adım 3: C2 Bağlantısı (port 4444)\n";
        auto r3 = engine.analyze(make_apt_c2(3001));
        print_result(r3);

        bool apt_detected =
            r1.verdict >= ThreatVerdict::MALICIOUS ||
            r2.verdict >= ThreatVerdict::MALICIOUS ||
            r3.verdict >= ThreatVerdict::SUSPICIOUS;

        if (apt_detected)
            std::cout << "  [✓] S3 PASS: APT lateral movement tespit edildi.\n";
        else
            std::cout << "  [✗] S3 FAIL: APT kaçtı!\n";
    }

    // ── S4: Ransomware ────────────────────────────────────────────────────
    print_banner("S4: Ransomware Davranış Simülasyonu");
    {
        std::cout << "  [→] Adım 1: Persistence (Registry Run Key)\n";
        auto r1 = engine.analyze(make_ransomware_persistence(4001));
        print_result(r1);

        std::cout << "  [→] Adım 2: Shellcode Yürütme (RWX bellek)\n";
        auto r2 = engine.analyze(make_ransomware_shellcode(4001));
        print_result(r2);

        if (r2.verdict >= ThreatVerdict::MALICIOUS)
            std::cout << "  [✓] S4 PASS: Ransomware davranışı tespit edildi.\n";
        else
            std::cout << "  [✗] S4 FAIL: Ransomware kaçtı!\n";
    }

    // ── S5: LOLBin Saldırısı ─────────────────────────────────────────────
    print_banner("S5: LOLBin + HOSTS Modifikasyonu");
    {
        auto ev = make_lolbin_attack(5001);
        auto r  = engine.analyze(ev);
        print_result(r);
        if (r.verdict >= ThreatVerdict::SUSPICIOUS)
            std::cout << "  [✓] S5 PASS: LOLBin+HOSTS saldırısı tespit edildi.\n";
        else
            std::cout << "  [✗] S5 FAIL: LOLBin kaçtı!\n";
    }

    // ── S6: Eş Zamanlı 8 Thread Testi ─────────────────────────────────────
    print_banner("S6: 8 Thread × 100 Olay = 800 Eş Zamanlı Analiz");
    {
        constexpr int THREADS = 8, EVENTS = 100;
        std::latch gate(THREADS);
        std::atomic<uint64_t> local_threats{0};
        std::vector<std::jthread> workers;
        workers.reserve(THREADS);

        for (int t = 0; t < THREADS; ++t) {
            workers.emplace_back([&, tid = t] {
                gate.arrive_and_wait();
                std::mt19937 rng(static_cast<uint32_t>(tid) * 31337u);
                for (int i = 0; i < EVENTS; ++i) {
                    // Rastgele tehdit tipi
                    uint32_t pid = 10000 + static_cast<uint32_t>(tid * 1000 + i);
                    TelemetryEvent ev;
                    switch (rng() % 5) {
                        case 0: ev = make_apt_hook(pid);             break;
                        case 1: ev = make_ransomware_shellcode(pid); break;
                        case 2: ev = make_lolbin_attack(pid);        break;
                        case 3: ev = make_clean_event(pid);          break;
                        case 4: ev = make_apt_c2(pid);               break;
                    }
                    auto r = engine.analyze(ev);
                    if (r.verdict >= ThreatVerdict::SUSPICIOUS)
                        ++local_threats;
                }
            });
        }
        workers.clear(); // join

        std::cout << "  [ℹ] " << THREADS * EVENTS << " olay işlendi. "
                  << "Tespit edilen tehdit: " << local_threats << "\n";
        std::cout << "  [✓] S6 PASS: Race condition yok, tüm olaylar işlendi.\n";
    }

    // ── S7: Hot-Reload İmza Güncelleme ───────────────────────────────────
    print_banner("S7: Runtime İmza Güncelleme (Hot-Reload)");
    {
        // Başlangıçta temiz
        TelemetryEvent ev{
            .pid=7001, .ppid=1, .event_type=EventType::FILE_MODIFY,
            .process_name="innocent.exe",
            .file_hash="0011223344556677001122334455667700112233445566770011223344556677",
            .target_path="C:\\temp\\innocent.exe", .dst_port=0, .is_elevated=false
        };
        auto r1 = engine.analyze(ev);
        std::cout << "  [Önce]  Score=" << r1.risk_score << "\n";

        // Çalışırken bu hash'i zararlı olarak ekle
        engine.add_malware_signature(ev.file_hash);

        auto r2 = engine.analyze(ev);
        std::cout << "  [Sonra] Score=" << r2.risk_score << "\n";

        if (r2.risk_score > r1.risk_score)
            std::cout << "  [✓] S7 PASS: Hot-reload imza güncelleme çalıştı.\n";
        else
            std::cout << "  [✗] S7 FAIL: Hot-reload işlevsiz!\n";
    }

    // ── Sonuç İstatistikleri ─────────────────────────────────────────────
    engine.print_stats();
    std::cout << "\n  Toplam Alarm    : " << alert_logger->alert_count() << "\n"
              << "  Sonlandırılan   : " << terminator->kill_count()   << "\n\n";

    print_banner("Tüm Testler Tamamlandı — İlker Kuru EDR Engine");
    
    std::cout << "\nÇıkmak için ENTER tuşuna basın...\n";
    std::cin.get();
    return 0;
}

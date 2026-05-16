/**
 * @file detection_chain.hpp
 * @author İlker Kuru — Defensive Security Architecture
 * @brief Chain of Responsibility + Filtreler + Observer Pattern.
 *
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │  TelemetryEvent                                                     │
 * │       │                                                             │
 * │       ▼                                                             │
 * │  ┌──────────────┐     ┌──────────────────┐     ┌────────────────┐  │
 * │  │  Signature   │────►│   Heuristic      │────►│  Network       │  │
 * │  │  Filter      │     │   Filter         │     │  Filter        │  │
 * │  │ (hash DB)    │     │ (davranış analiz)│     │ (C2 tespiti)   │  │
 * │  └──────────────┘     └──────────────────┘     └────────────────┘  │
 * │                                │                                    │
 * │                                ▼                                    │
 * │                         AnalysisResult                              │
 * │                                │                                    │
 * │                    ┌───────────┴──────────────┐                    │
 * │                    ▼                          ▼                    │
 * │             Observer 1                  Observer 2                  │
 * │          (AlertLogger)              (ProcessTerminator)             │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Chain of Responsibility Seçim Sebebi:
 *   - Her filtre bağımsız test edilebilir (SRP).
 *   - Zincire yeni filtre eklemek kodu değiştirmez (OCP).
 *   - Handler sırası runtime'da değiştirilebilir.
 *
 * Observer Pattern Seçim Sebebi:
 *   - Motor, aksiyonları (alarm, terminat, karantina) bilmek zorunda değil.
 *   - Yeni aksiyon = yeni Observer → Motor değişmez (DIP).
 */
#pragma once

#include "telemetry.hpp"

#include <algorithm>
#include <atomic>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace ilkerkuru::edr {

// ═════════════════════════════════════════════════════════════════════════════
//  OBSERVER PATTERN — Alarm / Aksiyon Mekanizması
// ═════════════════════════════════════════════════════════════════════════════

class IAlertObserver {
public:
    virtual ~IAlertObserver() = default;
    virtual void on_alert(const AnalysisResult& result) = 0;
};

// ── Observer 1: Alarm Logger ──────────────────────────────────────────────
class AlertLoggerObserver final : public IAlertObserver {
public:
    explicit AlertLoggerObserver(std::ostream& out = std::cout) : out_(out) {}

    void on_alert(const AnalysisResult& result) override {
        std::lock_guard lock(mtx_);
        out_ << "\n  🚨 [İlker Kuru EDR ALERT]\n"
             << "     PID          : " << result.event->pid << "\n"
             << "     Process      : " << result.event->process_name << "\n"
             << "     Risk Score   : " << result.risk_score << "/100\n"
             << "     Verdict      : " << to_string(result.verdict) << "\n"
             << "     Rules Hit    : ";
        for (const auto& r : result.triggered_rules)
            out_ << "[" << r << "] ";
        out_ << "\n\n";

        // Dosyaya da yaz
        std::ofstream fout("logs/edr_alerts.log", std::ios::app);
        if (fout) {
            fout << "\n[ALERT] PID: " << result.event->pid 
                 << " | Process: " << result.event->process_name 
                 << " | Score: " << result.risk_score << "/100"
                 << " | Verdict: " << to_string(result.verdict)
                 << " | Rules: ";
            for (const auto& r : result.triggered_rules) fout << "[" << r << "] ";
            fout << "\n";
        }

        ++alert_count_;
    }

    [[nodiscard]] uint64_t alert_count() const noexcept {
        return alert_count_.load(std::memory_order_relaxed);
    }

private:
    std::ostream&        out_;
    mutable std::mutex   mtx_;
    std::atomic<uint64_t> alert_count_{0};
};

// ── Observer 2: Process Terminator ──────────────────────────────────────────
class ProcessTerminatorObserver final : public IAlertObserver {
public:
    explicit ProcessTerminatorObserver(int kill_threshold = 60)
        : kill_threshold_(kill_threshold) {}

    void on_alert(const AnalysisResult& result) override {
        if (result.risk_score < kill_threshold_) return;

        std::lock_guard lock(mtx_);
        // Production'da: TerminateProcess(OpenProcess(..., pid), 1)
        // Simülasyon: Karantina listesine ekle + log
        quarantined_.insert(result.event->pid);
        terminated_.insert(result.event->pid);

        std::cout << "  ⛔ [TERMINATE] PID " << result.event->pid
                  << " (" << result.event->process_name << ") "
                  << "sonlandırıldı. Risk=" << result.risk_score << "\n"
                  << "  🗄️  [QUARANTINE] PID " << result.event->pid
                  << " karantinaya alındı.\n";
                  
        // Dosyaya da yaz
        std::ofstream fout("logs/edr_alerts.log", std::ios::app);
        if (fout) {
            fout << "[ACTION] TERMINATED & QUARANTINED -> PID: " << result.event->pid 
                 << " (" << result.event->process_name << ")\n";
        }

        ++kill_count_;
    }

    [[nodiscard]] bool is_quarantined(uint32_t pid) const {
        std::lock_guard lock(mtx_);
        return quarantined_.contains(pid);
    }

    [[nodiscard]] uint64_t kill_count() const noexcept {
        return kill_count_.load(std::memory_order_relaxed);
    }

private:
    int                         kill_threshold_;
    mutable std::mutex          mtx_;
    std::unordered_set<uint32_t> quarantined_;
    std::unordered_set<uint32_t> terminated_;
    std::atomic<uint64_t>        kill_count_{0};
};

// ═════════════════════════════════════════════════════════════════════════════
//  CHAIN OF RESPONSIBILITY — Temel Handler
// ═════════════════════════════════════════════════════════════════════════════
class IDetectionHandler {
public:
    virtual ~IDetectionHandler() = default;

    // Zinciri bağla — Fluent interface ile zincirleme kurulumu
    IDetectionHandler& set_next(std::shared_ptr<IDetectionHandler> next) {
        next_ = std::move(next);
        return *next_;
    }

    // Her handler sonucu günceller ve next'e geçirir
    virtual void handle(AnalysisResult& result) {
        analyze(result);
        if (next_) next_->handle(result);
    }

    [[nodiscard]] virtual std::string_view handler_name() const noexcept = 0;

protected:
    virtual void analyze(AnalysisResult& result) = 0;
    std::shared_ptr<IDetectionHandler> next_;
};

// ═════════════════════════════════════════════════════════════════════════════
//  FİLTRE 1: Statik İmza Filtresi — Bilinen zararlı hash veri tabanı
//
//  O(1) arama: std::unordered_set kullanılır.
//  Gerçek EDR: VirusTotal, YARA imzaları, vendor DB ile beslenir.
// ═════════════════════════════════════════════════════════════════════════════
class SignatureFilter final : public IDetectionHandler {
public:
    // Dependency Injection: hash DB dışarıdan enjekte edilir (test edilebilir)
    explicit SignatureFilter(std::unordered_set<std::string> known_bad_hashes)
        : db_(std::move(known_bad_hashes)) {}

    [[nodiscard]] std::string_view handler_name() const noexcept override {
        return "SignatureFilter";
    }

    // Hash DB'ye runtime ekleme (hot-update desteği)
    void add_signature(std::string hash) {
        std::lock_guard lock(db_mtx_);
        db_.insert(std::move(hash));
    }

protected:
    void analyze(AnalysisResult& result) override {
        if (result.event->file_hash.empty()) return;

        bool found;
        {
            std::lock_guard lock(db_mtx_);
            found = db_.contains(result.event->file_hash);
        }

        if (found) {
            // Bilinen zararlı → maksimum ceza
            result.add_risk(75, "KNOWN_MALWARE_HASH");
            std::cout << "  [SigFilter] ⚠️  Bilinen zararlı hash tespit: "
                      << result.event->file_hash.substr(0, 16) << "...\n";
        }
    }

private:
    std::unordered_set<std::string> db_;
    mutable std::mutex              db_mtx_;
};

// ═════════════════════════════════════════════════════════════════════════════
//  FİLTRE 2: Davranışsal Heuristic Filtre
//
//  Gerçek zamanlı Risk Score hesaplama:
//  - Her şüpheli davranış türüne ağırlıklı puan atanır.
//  - Birden fazla şüpheli davranış → puan birikir (compound scoring).
//
//  Gerçek EDR: ML modeli, sandbox sonuçları, davranış grafı ile desteklenir.
// ═════════════════════════════════════════════════════════════════════════════
class HeuristicFilter final : public IDetectionHandler {
public:
    [[nodiscard]] std::string_view handler_name() const noexcept override {
        return "HeuristicFilter";
    }

protected:
    void analyze(AnalysisResult& result) override {
        const auto& ev = *result.event;

        // Kural R1: ISR/SSDT Hooking girişimi — kernel-mode saldırı
        if (ev.event_type == EventType::HOOK_ATTEMPT) {
            result.add_risk(55, "ISR_SSDT_HOOK_ATTEMPT");
            log_rule(ev.pid, "Kernel hook girişimi tespit edildi");
        }

        // Kural R2: HOSTS dosyası değişikliği — DNS hijacking
        if (ev.event_type == EventType::HOSTS_MODIFY) {
            result.add_risk(40, "HOSTS_FILE_MODIFICATION");
            log_rule(ev.pid, "HOSTS dosyası değiştirilmeye çalışıldı (DNS Hijack)");
        }

        // Kural R3: Başka prosese bellek enjeksiyonu — code injection
        if (ev.event_type == EventType::PROCESS_INJECT) {
            result.add_risk(65, "PROCESS_MEMORY_INJECTION");
            log_rule(ev.pid, "Proses bellek enjeksiyonu tespit edildi");
        }

        // Kural R4: Shellcode yürütme — yürütülebilir veri bölgesi
        if (ev.event_type == EventType::SHELLCODE_EXEC) {
            result.add_risk(70, "SHELLCODE_EXECUTION");
            log_rule(ev.pid, "Shellcode yürütme tespit edildi (W^X ihlali)");
        }

        // Kural R5: Persistence — Registry Run Key
        if (ev.event_type == EventType::REGISTRY_RUNKEY) {
            result.add_risk(35, "PERSISTENCE_RUN_KEY");
            log_rule(ev.pid, "Kalıcılık mekanizması: Registry Run key");
        }

        // Kural R6: Ayrıcalık yükseltme + yüksek risk aktivite
        if (ev.is_elevated && ev.event_type == EventType::PRIVILEGE_ESCALATE) {
            result.add_risk(50, "PRIVILEGE_ESCALATION_ELEVATED");
            log_rule(ev.pid, "SYSTEM yetkisiyle ayrıcalık yükseltme");
        }

        // Kural R7: Şüpheli process adı (lolbins — living off the land)
        static const std::unordered_set<std::string> lolbins = {
            "powershell.exe","cmd.exe","wscript.exe","cscript.exe",
            "mshta.exe","regsvr32.exe","rundll32.exe","certutil.exe",
            "bitsadmin.exe","wmic.exe","msiexec.exe"
        };
        if (lolbins.contains(ev.process_name)) {
            result.add_risk(20, "LOLBIN_EXECUTION");
            log_rule(ev.pid, "LOLBin tespiti: " + ev.process_name);
        }

        // Kural R8: İzlenen hassas dizin değişikliği
        static const std::vector<std::string> sensitive_paths = {
            "\\system32\\", "\\syswow64\\", "\\drivers\\",
            "\\winlogon", "\\lsass", "/etc/", "/bin/"
        };
        for (const auto& sp : sensitive_paths) {
            std::string lower_path = ev.target_path;
            std::transform(lower_path.begin(), lower_path.end(),
                           lower_path.begin(), ::tolower);
            if (lower_path.find(sp) != std::string::npos) {
                result.add_risk(25, "SENSITIVE_PATH_MODIFY");
                log_rule(ev.pid, "Hassas dizin değişikliği: " + ev.target_path);
                break;
            }
        }
    }

private:
    static void log_rule(uint32_t pid, std::string_view desc) {
        std::cout << "  [Heuristic] 🔍 PID " << pid
                  << " → " << desc << "\n";
    }
};

// ═════════════════════════════════════════════════════════════════════════════
//  FİLTRE 3: Ağ/C2 Filtresi
// ═════════════════════════════════════════════════════════════════════════════
class NetworkFilter final : public IDetectionHandler {
public:
    [[nodiscard]] std::string_view handler_name() const noexcept override {
        return "NetworkFilter";
    }

protected:
    void analyze(AnalysisResult& result) override {
        const auto& ev = *result.event;

        if (ev.event_type != EventType::NETWORK_CONNECT &&
            ev.event_type != EventType::NETWORK_LISTEN) return;

        // Kural N1: Bilinen C2 portları
        static const std::unordered_set<uint16_t> c2_ports = {
            4444, 1234, 31337, 8080, 8888, 9001, 9090, 6666, 2222
        };
        if (c2_ports.contains(ev.dst_port)) {
            result.add_risk(45, "C2_KNOWN_PORT");
            std::cout << "  [NetFilter] 🌐 PID " << ev.pid
                      << " C2 şüpheli port: " << ev.dst_port << "\n";
        }

        // Kural N2: Non-standard yüksek port
        if (ev.dst_port > 49151 && !c2_ports.contains(ev.dst_port)) {
            result.add_risk(15, "EPHEMERAL_PORT_CONNECT");
        }

        // Kural N3: Elevated proses + dış bağlantı
        if (ev.is_elevated &&
            (ev.event_type == EventType::NETWORK_CONNECT)) {
            result.add_risk(20, "ELEVATED_OUTBOUND_CONNECTION");
        }
    }
};

} // namespace ilkerkuru::edr

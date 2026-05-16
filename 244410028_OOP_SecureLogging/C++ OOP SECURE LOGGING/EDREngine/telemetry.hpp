/**
 * @file telemetry.hpp
 * @author İlker Kuru — Defensive Security Architecture
 * @brief EDR telemetri veri modeli — işletim sistemi olaylarını temsil eder.
 *
 * TelemetryEvent sistemi kernel-mode driver veya ETW (Event Tracing for Windows)
 * üzerinden beslenir. Bu dosya o veri akışının veri sözleşmesini (data contract)
 * tanımlar.
 */
#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace ilkerkuru::edr {

// ─────────────────────────────────────────────────────────────────────────────
// Olay türleri — kernel telemetrisinden gelen event kategorileri
// ─────────────────────────────────────────────────────────────────────────────
enum class EventType : uint8_t {
    PROCESS_CREATE      = 0x01,  // Yeni proses oluşturma
    PROCESS_INJECT      = 0x02,  // Başka prosesin belleğine yazma (shellcode)
    FILE_MODIFY         = 0x10,  // Dosya değişikliği
    FILE_DELETE         = 0x11,  // Dosya silme
    HOSTS_MODIFY        = 0x12,  // HOSTS dosyası değişikliği (DNS hijack)
    REGISTRY_MODIFY     = 0x20,  // Registry yazma
    REGISTRY_RUNKEY     = 0x21,  // Persistence (Run key)
    NETWORK_CONNECT     = 0x30,  // Giden bağlantı
    NETWORK_LISTEN      = 0x31,  // Dinleme portu açma
    HOOK_ATTEMPT        = 0x40,  // IAT/SSDT hook girişimi
    PRIVILEGE_ESCALATE  = 0x50,  // Ayrıcalık yükseltme
    SHELLCODE_EXEC      = 0x60,  // Yürütülebilir bellek bölgesinde kod çalıştırma
};

[[nodiscard]] inline std::string_view to_string(EventType t) noexcept {
    switch (t) {
        case EventType::PROCESS_CREATE:     return "PROCESS_CREATE";
        case EventType::PROCESS_INJECT:     return "PROCESS_INJECT";
        case EventType::FILE_MODIFY:        return "FILE_MODIFY";
        case EventType::FILE_DELETE:        return "FILE_DELETE";
        case EventType::HOSTS_MODIFY:       return "HOSTS_MODIFY";
        case EventType::REGISTRY_MODIFY:    return "REGISTRY_MODIFY";
        case EventType::REGISTRY_RUNKEY:    return "REGISTRY_RUNKEY";
        case EventType::NETWORK_CONNECT:    return "NETWORK_CONNECT";
        case EventType::NETWORK_LISTEN:     return "NETWORK_LISTEN";
        case EventType::HOOK_ATTEMPT:       return "HOOK_ATTEMPT";
        case EventType::PRIVILEGE_ESCALATE: return "PRIVILEGE_ESCALATE";
        case EventType::SHELLCODE_EXEC:     return "SHELLCODE_EXEC";
    }
    return "UNKNOWN";
}

// ─────────────────────────────────────────────────────────────────────────────
// TelemetryEvent — Değer semantiği (Value Object), immutable after creation
// ─────────────────────────────────────────────────────────────────────────────
struct TelemetryEvent {
    uint32_t    pid;            // Proses ID
    uint32_t    ppid;           // Parent proses ID
    EventType   event_type;
    std::string process_name;   // Örn: "svchost.exe"
    std::string file_hash;      // SHA-256 hex (dosya olaylarında)
    std::string target_path;    // Hedef dosya/registry/IP
    uint16_t    dst_port;       // Ağ olaylarında hedef port
    bool        is_elevated;    // SYSTEM/Admin yetkisi var mı?

    // Olay zaman damgası (monotonic)
    std::chrono::steady_clock::time_point timestamp =
        std::chrono::steady_clock::now();

    // Ek meta veri (extensible, key-value)
    std::unordered_map<std::string, std::string> metadata;
};

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisResult — Zincir boyunca biriken analiz sonuçları
// ─────────────────────────────────────────────────────────────────────────────
enum class ThreatVerdict : uint8_t {
    CLEAN     = 0,
    SUSPICIOUS,
    MALICIOUS,
    CRITICAL
};

[[nodiscard]] inline std::string_view to_string(ThreatVerdict v) noexcept {
    switch(v) {
        case ThreatVerdict::CLEAN:     return "CLEAN";
        case ThreatVerdict::SUSPICIOUS:return "SUSPICIOUS";
        case ThreatVerdict::MALICIOUS: return "MALICIOUS";
        case ThreatVerdict::CRITICAL:  return "CRITICAL";
    }
    return "UNKNOWN";
}

struct AnalysisResult {
    const TelemetryEvent* event = nullptr;
    int   risk_score = 0;       // 0-100 arası kümülatif risk puanı
    ThreatVerdict verdict = ThreatVerdict::CLEAN;
    std::vector<std::string> triggered_rules; // Tetiklenen kural isimleri

    void add_risk(int score, std::string_view rule) {
        risk_score = std::min(100, risk_score + score);
        triggered_rules.emplace_back(rule);
        // Risk skoru eşiklerine göre verdict güncelle
        if      (risk_score >= 80) verdict = ThreatVerdict::CRITICAL;
        else if (risk_score >= 60) verdict = ThreatVerdict::MALICIOUS;
        else if (risk_score >= 30) verdict = ThreatVerdict::SUSPICIOUS;
    }
};

} // namespace ilkerkuru::edr

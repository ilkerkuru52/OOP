/**
 * @file edr_engine.hpp
 * @author İlker Kuru — Defensive Security Architecture
 * @brief EDR Orchestrator — Gerçek zamanlı telemetri analiz motoru.
 *
 * EDREngine şu sorumlulukları taşır:
 *   1. Tespit zincirini (Chain of Responsibility) kurar ve yönetir.
 *   2. Observer'ları (alarm, terminate, quarantine) kaydeder.
 *   3. Telemetri olaylarını eş zamanlı (concurrent) işler.
 *   4. İstatistik ve audit trail tutar.
 *
 * Neden Orchestrator ayrı?
 *   - Tek Sorumluluk (SRP): Motor yalnızca koordinasyondan sorumlu.
 *   - Handler ve Observer'lar motoru bilmiyor → gerçek bağımsızlık.
 */
#pragma once

#include "detection_chain.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace ilkerkuru::edr {

// ─────────────────────────────────────────────────────────────────────────────
// EDR Motoru — Orchestrator
// ─────────────────────────────────────────────────────────────────────────────
class EDREngine {
public:
    // Eşik değerleri: bu puanların üzerinde ilgili Observer çalışır
    static constexpr int ALERT_THRESHOLD     = 30;
    static constexpr int TERMINATE_THRESHOLD = 60;

    EDREngine() {
        build_chain();
    }

    // ── Observer Yönetimi (DIP: engine spesifik aksiyonları bilmiyor) ─────
    void register_observer(std::shared_ptr<IAlertObserver> obs) {
        std::lock_guard lock(obs_mtx_);
        observers_.push_back(std::move(obs));
    }

    // ── Ana Analiz Metodu ─────────────────────────────────────────────────
    /**
     * Telemetri olayını analiz zincirinden geçirir ve sonuca göre Observer'ları
     * tetikler. Thread-safe: birden fazla thread aynı anda çağırabilir.
     */
    [[nodiscard]] AnalysisResult analyze(const TelemetryEvent& event) {
        ++total_events_;

        AnalysisResult result;
        result.event = &event;

        // Chain of Responsibility başlat
        chain_head_->handle(result);

        // Eşik aşıldıysa tüm Observer'ları uyar
        if (result.risk_score >= ALERT_THRESHOLD) {
            ++threat_count_;
            notify_observers(result);
        }

        return result;
    }

    // ── İstatistikler ──────────────────────────────────────────────────────
    [[nodiscard]] uint64_t total_events() const noexcept {
        return total_events_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] uint64_t threat_count() const noexcept {
        return threat_count_.load(std::memory_order_relaxed);
    }

    void print_stats() const {
        std::cout << "\n╔══════════════════════════════════════════╗\n"
                  << "║  İlker Kuru EDR — Analiz İstatistikleri  ║\n"
                  << "╠══════════════════════════════════════════╣\n"
                  << "║  Toplam Olay      : "
                  << std::setw(20) << total_events() << " ║\n"
                  << "║  Tehdit Tespit    : "
                  << std::setw(20) << threat_count() << " ║\n"
                  << "╚══════════════════════════════════════════╝\n";
    }

    // ── Dinamik İmza Güncelleme (hot-reload) ──────────────────────────────
    void add_malware_signature(std::string hash) {
        if (sig_filter_) sig_filter_->add_signature(std::move(hash));
    }

private:
    void build_chain() {
        // Bilinen zararlı hash veri tabanı (gerçekte threat intel feed'den gelir)
        std::unordered_set<std::string> known_bad = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // boş (test)
            "aabbcc1122334455aabbcc1122334455aabbcc1122334455aabbcc1122334455", // simüle kötü
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", // simüle kötü
            "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"   // simüle kötü
        };

        // Zincir: SignatureFilter → HeuristicFilter → NetworkFilter
        auto sig_ptr = std::make_shared<SignatureFilter>(std::move(known_bad));
        sig_filter_ = sig_ptr.get();

        auto heuristic = std::make_shared<HeuristicFilter>();
        auto network   = std::make_shared<NetworkFilter>();

        // Bağlantı kur
        sig_ptr->set_next(heuristic);
        heuristic->set_next(network);

        chain_head_ = std::move(sig_ptr);
    }

    void notify_observers(const AnalysisResult& result) {
        std::lock_guard lock(obs_mtx_);
        for (auto& obs : observers_)
            obs->on_alert(result);
    }

    // Chain başı (sahiplik burada)
    std::shared_ptr<IDetectionHandler>      chain_head_;
    SignatureFilter*                         sig_filter_ = nullptr; // weak ref
    std::vector<std::shared_ptr<IAlertObserver>> observers_;
    mutable std::mutex                       obs_mtx_;

    std::atomic<uint64_t> total_events_{0};
    std::atomic<uint64_t> threat_count_{0};
};

} // namespace ilkerkuru::edr

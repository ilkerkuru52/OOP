/**
 * @file main_logger.cpp
 * @author İlker Kuru — Secure Systems Architecture
 * @brief SecureLogger agresif test senaryoları.
 *
 * Test Senaryoları:
 *   T1 — 16 concurrent thread, her biri 500 log → 8000 kayıt, race-condition testi.
 *   T2 — Farklı log seviyeleri ve filtre testi.
 *   T3 — Log dosyasını manuel bozarak HMAC integrity violation tespiti.
 *   T4 — ChaCha20 şifreleme/çözme round-trip doğrulaması.
 *   T5 — AES-256-CTR şifreleme/çözme round-trip doğrulaması.
 */
#include "secure_logger.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <latch>
#include <random>
#include <ranges>
#include <string>
#include <thread>
#include <vector>

using namespace ilkerkuru::crypto;
using namespace ilkerkuru::logging;

// ─── Yardımcılar ───────────────────────────────────────────────────────────
static void print_banner(std::string_view title) {
    std::cout << "\n╔══════════════════════════════════════════════════════╗\n"
              << "║  " << title;
    for (std::size_t i = title.size(); i < 52; ++i) std::cout << ' ';
    std::cout << "║\n"
              << "╚══════════════════════════════════════════════════════╝\n";
}

static void print_ok(std::string_view msg) {
    std::cout << "  [✓] " << msg << '\n';
}
static void print_fail(std::string_view msg) {
    std::cout << "  [✗] " << msg << '\n';
}

// ─── Test T4/T5: Şifreleme Round-Trip ─────────────────────────────────────
template<typename Enc>
void test_encrypt_roundtrip(Enc& enc, std::string_view algo) {
    const std::string original = "İlker Kuru — Kriptografik round-trip testi 🔐";
    auto ct = enc.encrypt(original);
    auto pt = enc.decrypt(std::span<const uint8_t>(ct.data(), ct.size()));

    if (pt == original) print_ok(std::string(algo) + " round-trip OK");
    else                print_fail(std::string(algo) + " round-trip FAILED");
}

// ─── Test T4: SHA-256 Doğrulaması ─────────────────────────────────────────
void test_sha256() {
    // NIST test vector: SHA-256("abc") = ba7816bf...
    const std::string input = "abc";
    auto digest = SHA256::hash(input);
    constexpr std::array<uint8_t, 32> expected = {
        0xba,0x78,0x16,0xbf, 0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde, 0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3, 0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61, 0xf2,0x00,0x15,0xad
    };
    if (digest == expected) print_ok("SHA-256 NIST test vector 'abc' OK");
    else                    print_fail("SHA-256 NIST test vector FAILED");
}

// ─── Ana Test Fonksiyonu ───────────────────────────────────────────────────
int main() {
    print_banner("İlker Kuru — SecureLogger Test Suite v1.0");

    // Log klasörünü oluştur
    std::filesystem::create_directory("logs");

    // ── T4: Kriptografik Primitive Doğrulaması ───────────────────────────
    print_banner("T4: Kriptografik Primitive Testi");
    test_sha256();

    // ChaCha20 round-trip
    ChaCha20Encryptor::Key   cc20_key{};
    ChaCha20Encryptor::Nonce cc20_nonce{};
    // Deterministik test anahtarı (gerçekte CSPRNG'den gelir)
    for (std::size_t i = 0; i < cc20_key.size();   ++i) cc20_key[i]   = uint8_t(i + 1);
    for (std::size_t i = 0; i < cc20_nonce.size(); ++i) cc20_nonce[i] = uint8_t(i + 0xA0);
    ChaCha20Encryptor cc20(cc20_key, cc20_nonce);
    test_encrypt_roundtrip(cc20, "ChaCha20");

    // AES-256-CTR round-trip
    AES256CTREncryptor::Key aes_key{};
    AES256CTREncryptor::IV  aes_iv{};
    for (std::size_t i = 0; i < aes_key.size(); ++i) aes_key[i] = uint8_t(i + 0x20);
    for (std::size_t i = 0; i < aes_iv.size();  ++i) aes_iv[i]  = uint8_t(i + 0x80);
    AES256CTREncryptor aes256(aes_key, aes_iv);
    test_encrypt_roundtrip(aes256, "AES-256-CTR");

    // HMAC doğrulama
    {
        const std::string key = "IlkerKuruHMACTestKey-2026";
        HMAC_SHA256 h(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(key.data()), key.size()));
        auto mac1 = h.compute("test message");
        auto mac2 = h.compute("test message");
        auto mac3 = h.compute("tampered!!");
        if (HMAC_SHA256::verify(mac1, mac2)) print_ok("HMAC aynı mesaj → eşit OK");
        else                                 print_fail("HMAC consistency FAILED");
        if (!HMAC_SHA256::verify(mac1, mac3)) print_ok("HMAC farklı mesaj → eşitsiz OK");
        else                                  print_fail("HMAC tamper detection FAILED");
    }

    // ── T1: Concurrent Logger Testi (16 thread × 500 log = 8000 kayıt) ──
    print_banner("T1: 16 Thread × 500 Log = 8000 Kayıt");

    constexpr int    THREAD_COUNT = 16;
    constexpr int    LOGS_PER_TH  = 500;
    const std::string LOG_FILE    = "logs/ilkerkuru_secure.log";
    const std::string HMAC_KEY    = "IlkerKuru-SuperSecret-HMAC-Key-2026!@#";

    // ChaCha20 ile logger oluştur
    auto enc = std::make_unique<ChaCha20Encryptor>(cc20_key, cc20_nonce);
    SecureLogger logger(std::move(enc), HMAC_KEY, LOG_FILE, LogLevel::TRACE);

    auto t_start = std::chrono::high_resolution_clock::now();

    // std::latch ile tüm thread'ler aynı anda başlar (gerçek race test)
    std::latch start_gate(THREAD_COUNT);
    std::vector<std::jthread> threads;
    threads.reserve(THREAD_COUNT);

    for (int t = 0; t < THREAD_COUNT; ++t) {
        threads.emplace_back([&, tid = t] {
            start_gate.arrive_and_wait(); // Senkron başlangıç noktası
            std::mt19937 rng(static_cast<uint32_t>(tid) * 12345u);
            for (int i = 0; i < LOGS_PER_TH; ++i) {
                auto lvl = static_cast<LogLevel>(rng() % 6);
                logger.log(lvl,
                    std::format("[Thread-{:02d}] Log #{:04d} — "
                                "Payload: deadbeef-{:08x}", tid, i, rng()));
            }
        });
    }
    threads.clear(); // jthread destructor → join

    logger.flush();
    auto t_end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();

    std::cout << "  [ℹ] Toplam yazılan: " << logger.total_written()
              << " / 8000 — Süre: " << ms << " ms\n";

    if (logger.total_written() == THREAD_COUNT * LOGS_PER_TH)
        print_ok("T1: Tüm kayıtlar eksiksiz yazıldı (veri kaybı yok)");
    else
        print_fail("T1: Kayıt sayısı tutarsız!");

    // ── T2: Log Seviyesi Filtresi ────────────────────────────────────────
    print_banner("T2: Log Seviyesi Filtresi (min=WARN)");
    {
        auto enc2 = std::make_unique<ChaCha20Encryptor>(cc20_key, cc20_nonce);
        SecureLogger filtered(std::move(enc2), HMAC_KEY,
                              "logs/ilkerkuru_filtered.log", LogLevel::WARN);
        filtered.trace("Bu görünmemeli");
        filtered.debug("Bu görünmemeli");
        filtered.info ("Bu görünmemeli");
        filtered.warn ("Bu görünmeli — WARN");
        filtered.error("Bu görünmeli — ERROR");
        filtered.critical("Bu görünmeli — CRITICAL");
        filtered.flush();
        if (filtered.total_written() == 3)
            print_ok("T2: Filtre doğru (sadece WARN/ERROR/CRITICAL yazıldı)");
        else
            print_fail("T2: Filtre tutarsız!");
    }

    // ── T3: HMAC Bütünlük İhlali Testi ──────────────────────────────────
    print_banner("T3: HMAC Integrity Violation Testi");
    {
        // Önceki log dosyasının 3. satırını boz
        std::ifstream  fin (LOG_FILE);
        std::string    content;
        std::string    line;
        std::vector<std::string> lines;
        while (std::getline(fin, line)) lines.push_back(line);
        fin.close();

        // 3. veri satırını bul ve ilk karakterini değiştir (tahrifat simülasyonu)
        int data_line = 0;
        for (auto& l : lines) {
            if (!l.empty() && l[0] != '#') {
                ++data_line;
                if (data_line == 3) {
                    l[0] = (l[0] == 'a') ? 'b' : 'a'; // 1 bit flip
                    break;
                }
            }
        }

        std::ofstream fout("logs/ilkerkuru_tampered.log");
        for (const auto& l : lines) fout << l << '\n';
        fout.close();

        // Bütünlük doğrula → 1 ihlal bekleniyor
        auto enc3 = std::make_unique<ChaCha20Encryptor>(cc20_key, cc20_nonce);
        auto verified = SecureLogger::verify_log_integrity(
            "logs/ilkerkuru_tampered.log", HMAC_KEY, std::move(enc3));

        auto total = static_cast<uint64_t>(
            std::ranges::count_if(lines,
                [](const std::string& l){ return !l.empty() && l[0] != '#'; }));

        if (verified < total)
            print_ok("T3: Tahrifat tespit edildi — HMAC integrity çalışıyor!");
        else
            print_fail("T3: Tahrifat tespit EDİLEMEDİ!");
    }

    // ── T5: AES-256-CTR Logger Testi ────────────────────────────────────
    print_banner("T5: AES-256-CTR Logger Testi");
    {
        auto enc5 = std::make_unique<AES256CTREncryptor>(aes_key, aes_iv);
        SecureLogger aes_logger(std::move(enc5), HMAC_KEY,
                                "logs/ilkerkuru_aes.log", LogLevel::INFO);
        for (int i = 0; i < 100; ++i)
            aes_logger.info(std::format("AES-256-CTR log #{:03d} — İlker Kuru", i));
        aes_logger.flush();
        if (aes_logger.total_written() == 100)
            print_ok("T5: AES-256-CTR — 100 kayıt yazıldı");
        else
            print_fail("T5: AES-256-CTR kayıt sayısı tutarsız");
    }

    print_banner("Tüm Testler Tamamlandı — İlker Kuru SecureLogger");
    std::cout << "\n  Log dosyaları:\n"
              << "    • logs/ilkerkuru_secure.log   — ChaCha20, 8000 kayıt\n"
              << "    • logs/ilkerkuru_filtered.log — Filtreli (WARN+)\n"
              << "    • logs/ilkerkuru_tampered.log — Tahrifat testi\n"
              << "    • logs/ilkerkuru_aes.log      — AES-256-CTR\n\n";
    std::cout << "\nÇıkmak için ENTER tuşuna basın...\n";
    std::cin.get();
    return 0;
}

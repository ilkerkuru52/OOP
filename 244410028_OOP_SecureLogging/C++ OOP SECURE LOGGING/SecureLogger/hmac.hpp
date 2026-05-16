/**
 * @file hmac.hpp
 * @author İlker Kuru — Secure Systems Architecture
 * @brief RFC 2104 uyumlu HMAC-SHA256 implementasyonu.
 *
 * Neden HMAC?
 *   - Şifreli log satırlarının post-hoc TAHRİF EDİLİP EDİLMEDİĞİNİ tespit eder.
 *   - Symmetric key ile hem üretici hem doğrulayıcı aynı gizli anahtarı paylaşır.
 *   - Constant-time compare ile timing saldırısı engellenmiştir.
 */
#pragma once

#include "sha256.hpp"
#include <algorithm>
#include <array>
#include <span>
#include <string_view>

namespace ilkerkuru::crypto {

class HMAC_SHA256 {
public:
    static constexpr std::size_t MAC_SIZE = SHA256::DIGEST_SIZE;
    using MAC = SHA256::Digest;

    // Anahtar enjeksiyonu constructor'da yapılır — RAII uyumlu
    explicit HMAC_SHA256(std::span<const uint8_t> key) noexcept {
        // RFC 2104: key > block_size ise önce SHA-256 ile kısalt
        std::array<uint8_t, SHA256::BLOCK_SIZE> k{};
        if (key.size() > SHA256::BLOCK_SIZE) {
            auto hk = SHA256::hash(key);
            std::copy(hk.begin(), hk.end(), k.begin());
        } else {
            std::copy(key.begin(), key.end(), k.begin());
        }
        // ipad (0x36) ve opad (0x5C) maskeleri oluştur
        for (std::size_t i = 0; i < SHA256::BLOCK_SIZE; ++i) {
            ipad_[i] = k[i] ^ 0x36u;
            opad_[i] = k[i] ^ 0x5Cu;
        }
    }

    explicit HMAC_SHA256(std::string_view key) noexcept
        : HMAC_SHA256(std::span<const uint8_t>(
              reinterpret_cast<const uint8_t*>(key.data()), key.size())) {}

    [[nodiscard]] MAC compute(std::span<const uint8_t> msg) const noexcept {
        // Inner: H(ipad || message)
        SHA256 inner;
        inner.update(std::span<const uint8_t>(ipad_.data(), ipad_.size()));
        inner.update(msg);
        auto ih = inner.finalize();

        // Outer: H(opad || inner_hash)
        SHA256 outer;
        outer.update(std::span<const uint8_t>(opad_.data(), opad_.size()));
        outer.update(std::span<const uint8_t>(ih.data(), ih.size()));
        return outer.finalize();
    }

    [[nodiscard]] MAC compute(std::string_view msg) const noexcept {
        return compute(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(msg.data()), msg.size()));
    }

    // Constant-time karşılaştırma — timing attack'a karşı zorunlu
    [[nodiscard]] static bool verify(const MAC& expected,
                                     const MAC& actual) noexcept {
        uint8_t diff = 0;
        for (std::size_t i = 0; i < MAC_SIZE; ++i)
            diff |= expected[i] ^ actual[i];
        return diff == 0;
    }

private:
    std::array<uint8_t, SHA256::BLOCK_SIZE> ipad_{};
    std::array<uint8_t, SHA256::BLOCK_SIZE> opad_{};
};

} // namespace ilkerkuru::crypto

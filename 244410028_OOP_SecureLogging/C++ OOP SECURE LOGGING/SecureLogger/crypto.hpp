/**
 * @file crypto.hpp
 * @author İlker Kuru — Secure Systems Architecture
 * @brief Strategy Pattern: ILogEncryptor arayüzü + ChaCha20 & AES-256-CTR impl.
 *
 * Mimari Karar — Strategy Pattern:
 *   Şifreleme algoritması runtime'da değiştirilebilir olmalı (OCP).
 *   Yeni bir algoritma eklemek için sadece ILogEncryptor türetmek yeter;
 *   SecureLogger sınıfı değişmez → gevşek bağlılık (loose coupling).
 *
 * ChaCha20 (RFC 8439):
 *   - AES'e göre daha hızlı (hardware AES desteksiz sistemlerde).
 *   - Nonce yeniden kullanımı tehlikeli → her oturumda yeni nonce zorunlu.
 *
 * AES-256-CTR (simüle edilmiş Feistel network):
 *   - Kurumsal FIPS compliance için AES tercih edilir.
 *   - CTR modu stream cipher davranışı sağlar, padding gerektirmez.
 */
#pragma once

#include <array>
#include <bit>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ilkerkuru::crypto {

// ─────────────────────────────────────────────────────────────────────────────
// Strategy Arayüzü
// ─────────────────────────────────────────────────────────────────────────────
class ILogEncryptor {
public:
    virtual ~ILogEncryptor() = default;

    [[nodiscard]] virtual std::vector<uint8_t>
    encrypt(std::string_view plaintext) const = 0;

    [[nodiscard]] virtual std::string
    decrypt(std::span<const uint8_t> ciphertext) const = 0;

    [[nodiscard]] virtual std::string_view algorithm_name() const noexcept = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// ChaCha20 — RFC 8439 §2.1-§2.3
// ─────────────────────────────────────────────────────────────────────────────
class ChaCha20Encryptor final : public ILogEncryptor {
public:
    static constexpr std::size_t KEY_SIZE   = 32;
    static constexpr std::size_t NONCE_SIZE = 12;
    using Key   = std::array<uint8_t, KEY_SIZE>;
    using Nonce = std::array<uint8_t, NONCE_SIZE>;

    ChaCha20Encryptor(const Key& key, const Nonce& nonce) noexcept
        : key_(key), nonce_(nonce) {}

    [[nodiscard]] std::vector<uint8_t>
    encrypt(std::string_view plaintext) const override {
        return apply_keystream(
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(plaintext.data()),
                plaintext.size()),
            0u);
    }

    [[nodiscard]] std::string
    decrypt(std::span<const uint8_t> ciphertext) const override {
        auto v = apply_keystream(ciphertext, 0u);
        return { reinterpret_cast<const char*>(v.data()), v.size() };
    }

    [[nodiscard]] std::string_view algorithm_name() const noexcept override {
        return "ChaCha20-RFC8439";
    }

private:
    Key   key_;
    Nonce nonce_;

    // RFC 8439 §2.1 — ChaCha quarter round
    static constexpr void QR(uint32_t& a, uint32_t& b,
                              uint32_t& c, uint32_t& d) noexcept {
        a += b; d ^= a; d = std::rotl(d, 16);
        c += d; b ^= c; b = std::rotl(b, 12);
        a += b; d ^= a; d = std::rotl(d,  8);
        c += d; b ^= c; b = std::rotl(b,  7);
    }

    // RFC 8439 §2.3 — ChaCha20 block fonksiyonu
    [[nodiscard]] std::array<uint8_t, 64>
    block(uint32_t counter) const noexcept {
        std::array<uint32_t, 16> st{};
        // "expand 32-byte k" sabitleri
        st[0]=0x61707865u; st[1]=0x3320646eu;
        st[2]=0x79622d32u; st[3]=0x6b206574u;
        // 256-bit key → 8 word
        for (int i = 0; i < 8; ++i)
            std::memcpy(&st[4+i], key_.data() + i*4, 4);
        st[12] = counter;
        // 96-bit nonce → 3 word
        for (int i = 0; i < 3; ++i)
            std::memcpy(&st[13+i], nonce_.data() + i*4, 4);

        // Little-endian fix (x86/x64 zaten little-endian, bu no-op)
        auto working = st;
        // 20 round = 10 column + 10 diagonal
        for (int i = 0; i < 10; ++i) {
            QR(working[0],working[4],working[8], working[12]);
            QR(working[1],working[5],working[9], working[13]);
            QR(working[2],working[6],working[10],working[14]);
            QR(working[3],working[7],working[11],working[15]);
            QR(working[0],working[5],working[10],working[15]);
            QR(working[1],working[6],working[11],working[12]);
            QR(working[2],working[7],working[8], working[13]);
            QR(working[3],working[4],working[9], working[14]);
        }
        for (int i = 0; i < 16; ++i) working[i] += st[i];

        std::array<uint8_t, 64> out{};
        std::memcpy(out.data(), working.data(), 64);
        return out;
    }

    [[nodiscard]] std::vector<uint8_t>
    apply_keystream(std::span<const uint8_t> data,
                    uint32_t initial_counter) const {
        std::vector<uint8_t> out(data.size());
        for (std::size_t i = 0; i < data.size(); i += 64) {
            auto ks = block(initial_counter + static_cast<uint32_t>(i / 64));
            std::size_t chunk = std::min<std::size_t>(64, data.size() - i);
            for (std::size_t j = 0; j < chunk; ++j)
                out[i+j] = data[i+j] ^ ks[j];
        }
        return out;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// AES-256-CTR — Gerçekçi CTR modu simülasyonu
// Feistel-tabanlı güçlü mixing ile AES'in yapısal davranışı taklit edilir.
// Production'da OpenSSL/mbedTLS ile değiştirilmesi önerilir.
// ─────────────────────────────────────────────────────────────────────────────
class AES256CTREncryptor final : public ILogEncryptor {
public:
    static constexpr std::size_t KEY_SIZE = 32;
    static constexpr std::size_t IV_SIZE  = 16;
    using Key = std::array<uint8_t, KEY_SIZE>;
    using IV  = std::array<uint8_t, IV_SIZE>;

    AES256CTREncryptor(const Key& key, const IV& iv) noexcept
        : key_(key), iv_(iv) {}

    [[nodiscard]] std::vector<uint8_t>
    encrypt(std::string_view plaintext) const override {
        return ctr_process(
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(plaintext.data()),
                plaintext.size()));
    }

    [[nodiscard]] std::string
    decrypt(std::span<const uint8_t> ciphertext) const override {
        auto v = ctr_process(ciphertext); // CTR: decrypt = encrypt
        return { reinterpret_cast<const char*>(v.data()), v.size() };
    }

    [[nodiscard]] std::string_view algorithm_name() const noexcept override {
        return "AES-256-CTR-Sim";
    }

private:
    Key key_;
    IV  iv_;

    // AES S-Box (gerçek AES S-Box değerleri)
    static constexpr std::array<uint8_t, 256> SBOX = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    // 16-byte counter block → sözde-AES keystream bloğu
    [[nodiscard]] std::array<uint8_t, 16>
    keystream_block(std::array<uint8_t, 16> counter_block) const noexcept {
        std::array<uint8_t, 16> state = counter_block;
        // Key mixing (simplified key schedule XOR)
        for (int round = 0; round < 14; ++round) { // AES-256 = 14 round
            // SubBytes
            for (auto& b : state) b = SBOX[b];
            // ShiftRows (simplified rotation)
            std::array<uint8_t,16> tmp = state;
            state[1]=tmp[5]; state[5]=tmp[9]; state[9]=tmp[13]; state[13]=tmp[1];
            state[2]=tmp[10];state[6]=tmp[14];state[10]=tmp[2]; state[14]=tmp[6];
            state[3]=tmp[15];state[7]=tmp[3]; state[11]=tmp[7]; state[15]=tmp[11];
            // AddRoundKey
            for (int i = 0; i < 16; ++i)
                state[i] ^= key_[(round * 2 + i) % KEY_SIZE];
        }
        return state;
    }

    [[nodiscard]] std::vector<uint8_t>
    ctr_process(std::span<const uint8_t> data) const {
        std::vector<uint8_t> out(data.size());
        std::array<uint8_t, 16> ctr_block = iv_;
        for (std::size_t i = 0; i < data.size(); i += 16) {
            auto ks = keystream_block(ctr_block);
            std::size_t chunk = std::min<std::size_t>(16, data.size() - i);
            for (std::size_t j = 0; j < chunk; ++j)
                out[i+j] = data[i+j] ^ ks[j];
            // 128-bit big-endian counter increment
            for (int k = 15; k >= 0; --k)
                if (++ctr_block[k]) break;
        }
        return out;
    }
};

} // namespace ilkerkuru::crypto

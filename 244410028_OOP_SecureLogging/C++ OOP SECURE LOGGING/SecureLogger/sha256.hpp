/**
 * @file sha256.hpp
 * @author İlker Kuru — Secure Systems Architecture
 * @brief FIPS 180-4 uyumlu, dış bağımlılıksız gerçek SHA-256 implementasyonu.
 *
 * Neden SHA-256?
 *   - Collision-resistant, pre-image resistant.
 *   - NIST onaylı; kurumsal ortamlarda zorunlu.
 *   - HMAC'ın kriptografik temeli olarak kullanılır.
 */
#pragma once

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

namespace ilkerkuru::crypto {

class SHA256 {
public:
    static constexpr std::size_t BLOCK_SIZE  = 64;
    static constexpr std::size_t DIGEST_SIZE = 32;
    using Digest = std::array<uint8_t, DIGEST_SIZE>;

    SHA256() noexcept { reset(); }

    void reset() noexcept {
        // FIPS 180-4 §5.3.3 — Initial hash values (ilk 8 asal sayının
        // kareköklerinin kesirli kısımları)
        state_[0] = 0x6a09e667u; state_[1] = 0xbb67ae85u;
        state_[2] = 0x3c6ef372u; state_[3] = 0xa54ff53au;
        state_[4] = 0x510e527fu; state_[5] = 0x9b05688cu;
        state_[6] = 0x1f83d9abu; state_[7] = 0x5be0cd19u;
        bit_count_ = 0; buf_len_ = 0;
    }

    void update(std::span<const uint8_t> data) noexcept {
        bit_count_ += static_cast<uint64_t>(data.size()) * 8u;
        std::size_t off = 0;

        if (buf_len_ > 0) {
            std::size_t take = std::min(BLOCK_SIZE - buf_len_, data.size());
            std::memcpy(buf_.data() + buf_len_, data.data(), take);
            buf_len_ += take; off += take;
            if (buf_len_ == BLOCK_SIZE) { process(buf_.data()); buf_len_ = 0; }
        }
        while (off + BLOCK_SIZE <= data.size()) {
            process(data.data() + off); off += BLOCK_SIZE;
        }
        if (off < data.size()) {
            std::size_t rem = data.size() - off;
            std::memcpy(buf_.data(), data.data() + off, rem);
            buf_len_ = rem;
        }
    }

    void update(std::string_view sv) noexcept {
        update(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(sv.data()), sv.size()));
    }

    [[nodiscard]] Digest finalize() noexcept {
        // Padding: 0x80 || zeroes || 64-bit big-endian bit count
        uint8_t pad[128]{};
        pad[0] = 0x80u;
        std::size_t pad_len = (buf_len_ < 56) ? (56 - buf_len_) : (120 - buf_len_);
        update(std::span<const uint8_t>(pad, pad_len));
        uint64_t bc_be = be64(bit_count_);
        update(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(&bc_be), 8));

        Digest d{};
        for (int i = 0; i < 8; ++i) {
            uint32_t w = be32(state_[i]);
            std::memcpy(d.data() + i * 4, &w, 4);
        }
        return d;
    }

    [[nodiscard]] static Digest hash(std::span<const uint8_t> data) noexcept {
        SHA256 c; c.update(data); return c.finalize();
    }
    [[nodiscard]] static Digest hash(std::string_view sv) noexcept {
        SHA256 c; c.update(sv); return c.finalize();
    }

private:
    // FIPS 180-4 §4.2.2 — SHA-256 round constants
    static constexpr std::array<uint32_t, 64> K = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
        0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
        0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
        0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
        0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
        0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
        0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
        0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
        0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };

    std::array<uint32_t, 8>         state_{};
    std::array<uint8_t, BLOCK_SIZE> buf_{};
    uint64_t                        bit_count_ = 0;
    std::size_t                     buf_len_   = 0;

    static constexpr uint32_t rotr(uint32_t x, int n) noexcept { return std::rotr(x, n); }
    static constexpr uint32_t Ch (uint32_t e,uint32_t f,uint32_t g) noexcept { return (e&f)^(~e&g); }
    static constexpr uint32_t Maj(uint32_t a,uint32_t b,uint32_t c) noexcept { return (a&b)^(a&c)^(b&c); }
    static constexpr uint32_t S0(uint32_t a) noexcept { return rotr(a,2)^rotr(a,13)^rotr(a,22); }
    static constexpr uint32_t S1(uint32_t e) noexcept { return rotr(e,6)^rotr(e,11)^rotr(e,25); }
    static constexpr uint32_t s0(uint32_t x) noexcept { return rotr(x,7)^rotr(x,18)^(x>>3); }
    static constexpr uint32_t s1(uint32_t x) noexcept { return rotr(x,17)^rotr(x,19)^(x>>10); }

    void process(const uint8_t* blk) noexcept {
        std::array<uint32_t, 64> W{};
        for (int i = 0; i < 16; ++i)
            W[i] = (uint32_t(blk[i*4])<<24)|(uint32_t(blk[i*4+1])<<16)|
                   (uint32_t(blk[i*4+2])<<8)| uint32_t(blk[i*4+3]);
        for (int i = 16; i < 64; ++i)
            W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];

        auto [a,b,c,d,e,f,g,h] = state_;
        for (int i = 0; i < 64; ++i) {
            uint32_t T1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i];
            uint32_t T2 = S0(a) + Maj(a,b,c);
            h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
        }
        state_[0]+=a; state_[1]+=b; state_[2]+=c; state_[3]+=d;
        state_[4]+=e; state_[5]+=f; state_[6]+=g; state_[7]+=h;
    }

    static constexpr uint32_t be32(uint32_t x) noexcept {
        if constexpr (std::endian::native == std::endian::big) return x;
        return ((x&0xFF000000u)>>24)|((x&0x00FF0000u)>>8)|
               ((x&0x0000FF00u)<<8) |((x&0x000000FFu)<<24);
    }
    static constexpr uint64_t be64(uint64_t x) noexcept {
        if constexpr (std::endian::native == std::endian::big) return x;
        return ((x&0xFF00000000000000ull)>>56)|((x&0x00FF000000000000ull)>>40)|
               ((x&0x0000FF0000000000ull)>>24)|((x&0x000000FF00000000ull)>> 8)|
               ((x&0x00000000FF000000ull)<< 8)|((x&0x0000000000FF0000ull)<<24)|
               ((x&0x000000000000FF00ull)<<40)|((x&0x00000000000000FFull)<<56);
    }
};

} // namespace ilkerkuru::crypto

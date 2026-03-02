#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <optional>
#include <sstream>
#include <iomanip>
#include <cwctype>
#include <cstring>

namespace guard::cfg
{
    // -------- Manual PBKDF2-HMAC-SHA256 (no BCrypt dependency) --------
    namespace detail
    {
        inline void Sha256ProcessBlock(const std::uint8_t* block, std::uint32_t* state)
        {
            static const std::uint32_t K[64] = {
                0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
                0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
                0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
                0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
                0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
                0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
                0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
                0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
            };
            std::uint32_t W[64];
            for (int t = 0; t < 16; ++t)
                W[t] = (static_cast<std::uint32_t>(block[t*4]) << 24) | (static_cast<std::uint32_t>(block[t*4+1]) << 16)
                     | (static_cast<std::uint32_t>(block[t*4+2]) << 8) | static_cast<std::uint32_t>(block[t*4+3]);
            for (int t = 16; t < 64; ++t) {
                std::uint32_t s0 = ((W[t-15] >> 7) | (W[t-15] << 25)) ^ ((W[t-15] >> 18) | (W[t-15] << 14)) ^ (W[t-15] >> 3);
                std::uint32_t s1 = ((W[t-2] >> 17) | (W[t-2] << 15)) ^ ((W[t-2] >> 19) | (W[t-2] << 13)) ^ (W[t-2] >> 10);
                W[t] = W[t-16] + s0 + W[t-7] + s1;
            }
            std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6], h = state[7];
            for (int t = 0; t < 64; ++t) {
                std::uint32_t S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
                std::uint32_t ch = (e & f) ^ ((~e) & g);
                std::uint32_t t1 = h + S1 + ch + K[t] + W[t];
                std::uint32_t S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
                std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                std::uint32_t t2 = S0 + maj;
                h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
            }
            state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e; state[5] += f; state[6] += g; state[7] += h;
        }

        inline void Sha256(const std::uint8_t* data, size_t len, std::uint8_t out[32])
        {
            std::uint32_t state[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
            std::uint8_t block[64];
            size_t i = 0;
            while (i + 64 <= len) {
                Sha256ProcessBlock(data + i, state);
                i += 64;
            }
            size_t remainder = len - i;
            std::memcpy(block, data + i, remainder);
            block[remainder] = 0x80;
            std::memset(block + remainder + 1, 0, 64 - remainder - 1);
            if (remainder >= 56) {
                Sha256ProcessBlock(block, state);
                std::memset(block, 0, 56);
            }
            std::uint64_t bitLen = len * 8u;
            block[63] = static_cast<std::uint8_t>(bitLen);
            block[62] = static_cast<std::uint8_t>(bitLen >> 8);
            block[61] = static_cast<std::uint8_t>(bitLen >> 16);
            block[60] = static_cast<std::uint8_t>(bitLen >> 24);
            block[59] = static_cast<std::uint8_t>(bitLen >> 32);
            block[58] = static_cast<std::uint8_t>(bitLen >> 40);
            block[57] = static_cast<std::uint8_t>(bitLen >> 48);
            block[56] = static_cast<std::uint8_t>(bitLen >> 56);
            Sha256ProcessBlock(block, state);
            for (int j = 0; j < 8; ++j) {
                out[j*4]     = static_cast<std::uint8_t>(state[j] >> 24);
                out[j*4 + 1] = static_cast<std::uint8_t>(state[j] >> 16);
                out[j*4 + 2] = static_cast<std::uint8_t>(state[j] >> 8);
                out[j*4 + 3] = static_cast<std::uint8_t>(state[j]);
            }
        }

        inline void HmacSha256(const std::uint8_t* key, size_t keyLen, const std::uint8_t* msg, size_t msgLen, std::uint8_t out[32])
        {
            std::uint8_t keyBuf[64] = {};
            if (keyLen > 64) {
                Sha256(key, keyLen, keyBuf);
                key = keyBuf;
                keyLen = 32;
            } else if (keyLen < 64) {
                std::memcpy(keyBuf, key, keyLen);
            } else {
                std::memcpy(keyBuf, key, 64);
            }
            std::uint8_t ipad[64], opad[64];
            for (int i = 0; i < 64; ++i) {
                ipad[i] = keyBuf[i] ^ 0x36u;
                opad[i] = keyBuf[i] ^ 0x5cu;
            }
            std::uint8_t inner[64 + 32];
            std::memcpy(inner, ipad, 64);
            std::memcpy(inner + 64, msg, msgLen);
            std::uint8_t innerHash[32];
            Sha256(inner, 64 + msgLen, innerHash);
            std::uint8_t outer[64 + 32];
            std::memcpy(outer, opad, 64);
            std::memcpy(outer + 64, innerHash, 32);
            Sha256(outer, 96, out);
        }

        inline std::vector<std::uint8_t> Pbkdf2HmacSha256Manual(
            const std::uint8_t* password, size_t passwordLen,
            const std::uint8_t* salt, size_t saltLen,
            DWORD iterations, size_t outLen)
        {
            if (outLen == 0 || saltLen == 0 || iterations == 0) return {};
            std::vector<std::uint8_t> out;
            out.reserve(outLen);
            size_t blockIndex = 1;
            while (out.size() < outLen) {
                std::uint8_t block[32];
                std::uint8_t u[32];
                std::uint8_t blockInput[64];
                size_t saltBlockLen = saltLen + 4;
                if (saltBlockLen > 64) return {};
                std::memcpy(blockInput, salt, saltLen);
                blockInput[saltLen]     = static_cast<std::uint8_t>(blockIndex >> 24);
                blockInput[saltLen + 1] = static_cast<std::uint8_t>(blockIndex >> 16);
                blockInput[saltLen + 2] = static_cast<std::uint8_t>(blockIndex >> 8);
                blockInput[saltLen + 3] = static_cast<std::uint8_t>(blockIndex);
                HmacSha256(password, passwordLen, blockInput, saltBlockLen, u);
                std::memcpy(block, u, 32);
                for (DWORD c = 1; c < iterations; ++c) {
                    HmacSha256(password, passwordLen, u, 32, u);
                    for (int i = 0; i < 32; ++i) block[i] ^= u[i];
                }
                for (size_t i = 0; i < 32 && out.size() < outLen; ++i)
                    out.push_back(block[i]);
                ++blockIndex;
            }
            out.resize(outLen);
            return out;
        }
    }
    enum class Mode
    {
        Observe,
        Block,
    };

    inline std::wstring ReadIniString(const std::wstring& path, const wchar_t* section, const wchar_t* key, const wchar_t* def = L"")
    {
        wchar_t buf[2048] = {};
        GetPrivateProfileStringW(section, key, def, buf, static_cast<DWORD>(std::size(buf)), path.c_str());
        return buf;
    }

    inline DWORD ReadIniDword(const std::wstring& path, const wchar_t* section, const wchar_t* key, DWORD def)
    {
        return GetPrivateProfileIntW(section, key, def, path.c_str());
    }

    inline bool WriteIniString(const std::wstring& path, const wchar_t* section, const wchar_t* key, const std::wstring& value)
    {
        return WritePrivateProfileStringW(section, key, value.c_str(), path.c_str()) != FALSE;
    }

    inline std::vector<std::uint8_t> HexToBytes(const std::wstring& hex)
    {
        std::vector<std::uint8_t> out;
        if (hex.size() % 2 != 0) return out;
        out.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2)
        {
            unsigned int v = 0;
            std::wstringstream ss;
            ss << std::hex << hex.substr(i, 2);
            ss >> v;
            out.push_back(static_cast<std::uint8_t>(v & 0xFF));
        }
        return out;
    }

    inline std::wstring BytesToHex(const std::vector<std::uint8_t>& bytes)
    {
        std::wstringstream ss;
        ss << std::hex << std::setfill(L'0');
        for (auto b : bytes)
            ss << std::setw(2) << static_cast<int>(b);
        return ss.str();
    }

    inline std::vector<std::uint8_t> RandomBytes(size_t n)
    {
        if (n == 0) return {};
        std::vector<std::uint8_t> out(n);
        HCRYPTPROV h = 0;
        if (!CryptAcquireContextW(&h, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
            return {};
        BOOL ok = CryptGenRandom(h, static_cast<DWORD>(out.size()), out.data());
        CryptReleaseContext(h, 0);
        return ok ? out : std::vector<std::uint8_t>{};
    }

    inline std::vector<std::uint8_t> Pbkdf2Sha256(const std::wstring& password, const std::vector<std::uint8_t>& salt, DWORD iterations, size_t outLen)
    {
        if (outLen == 0 || salt.empty() || iterations == 0) return {};
        auto* pw = reinterpret_cast<const std::uint8_t*>(password.c_str());
        size_t pwBytes = password.size() * sizeof(wchar_t);
        return detail::Pbkdf2HmacSha256Manual(pw, pwBytes, salt.data(), salt.size(), iterations, outLen);
    }

    struct Settings
    {
        Mode mode = Mode::Block;
        DWORD hookTimeoutMs = 30'000;
        DWORD tokenSeconds = 300;
        DWORD pbkdf2Iterations = 200'000;
        std::vector<std::uint8_t> salt;
        std::vector<std::uint8_t> hash;
        // 授权密码（放行关机/重启用）；与安装/卸载密码分离。
        DWORD authTokenIterations = 200'000;
        std::vector<std::uint8_t> authTokenSalt;
        std::vector<std::uint8_t> authTokenHash;
    };

    inline Settings Load(const std::wstring& iniPath)
    {
        Settings s{};
        auto lower = [](std::wstring v) {
            for (auto& ch : v) ch = static_cast<wchar_t>(towlower(ch));
            return v;
        };

        std::wstring mode = lower(ReadIniString(iniPath, L"General", L"Mode", L"block"));
        if (mode == L"observe") s.mode = Mode::Observe;

        s.hookTimeoutMs = ReadIniDword(iniPath, L"Behavior", L"HookTimeoutMs", 30'000);
        s.tokenSeconds = ReadIniDword(iniPath, L"Auth", L"TokenSeconds", 300);
        s.pbkdf2Iterations = ReadIniDword(iniPath, L"Auth", L"Iterations", 200'000);

        s.salt = HexToBytes(ReadIniString(iniPath, L"Auth", L"SaltHex", L""));
        s.hash = HexToBytes(ReadIniString(iniPath, L"Auth", L"HashHex", L""));

        s.authTokenIterations = ReadIniDword(iniPath, L"Auth", L"AuthTokenIterations", 200'000);
        s.authTokenSalt = HexToBytes(ReadIniString(iniPath, L"Auth", L"AuthTokenSaltHex", L""));
        s.authTokenHash = HexToBytes(ReadIniString(iniPath, L"Auth", L"AuthTokenHashHex", L""));
        return s;
    }

    inline bool HasPasswordConfigured(const Settings& s)
    {
        return !s.salt.empty() && !s.hash.empty();
    }

    inline bool VerifyPassword(const Settings& s, const std::wstring& password)
    {
        if (!HasPasswordConfigured(s)) return false;
        auto derived = Pbkdf2Sha256(password, s.salt, s.pbkdf2Iterations, s.hash.size());
        if (derived.size() != s.hash.size()) return false;
        std::uint8_t diff = 0;
        for (size_t i = 0; i < derived.size(); ++i)
            diff |= static_cast<std::uint8_t>(derived[i] ^ s.hash[i]);
        return diff == 0;
    }

    inline bool SetPassword(const std::wstring& iniPath, const std::wstring& password, DWORD iterations = 200'000)
    {
        if (iterations < 10'000) iterations = 10'000;
        if (iterations > 5'000'000) iterations = 5'000'000;

        std::vector<std::uint8_t> salt = RandomBytes(16);
        if (salt.empty()) return false;
        std::vector<std::uint8_t> hash = Pbkdf2Sha256(password, salt, iterations, 32);
        if (hash.empty()) return false;

        if (!WriteIniString(iniPath, L"Auth", L"SaltHex", BytesToHex(salt))) return false;
        if (!WriteIniString(iniPath, L"Auth", L"HashHex", BytesToHex(hash))) return false;
        if (!WriteIniString(iniPath, L"Auth", L"Iterations", std::to_wstring(iterations))) return false;
        return true;
    }

    // -------- 授权密码（仅放行关机/重启用）；未设则放行时用维护密码。安装/卸载只管维护密码。--------
    inline bool HasAuthTokenConfigured(const Settings& s)
    {
        return !s.authTokenSalt.empty() && !s.authTokenHash.empty();
    }

    inline bool VerifyAuthToken(const Settings& s, const std::wstring& password)
    {
        if (!HasAuthTokenConfigured(s)) return false;
        auto derived = Pbkdf2Sha256(password, s.authTokenSalt, s.authTokenIterations, s.authTokenHash.size());
        if (derived.size() != s.authTokenHash.size()) return false;
        std::uint8_t diff = 0;
        for (size_t i = 0; i < derived.size(); ++i)
            diff |= static_cast<std::uint8_t>(derived[i] ^ s.authTokenHash[i]);
        return diff == 0;
    }

    inline bool SetAuthToken(const std::wstring& iniPath, const std::wstring& password, DWORD iterations = 200'000)
    {
        if (iterations < 10'000) iterations = 10'000;
        if (iterations > 5'000'000) iterations = 5'000'000;

        std::vector<std::uint8_t> salt = RandomBytes(16);
        if (salt.empty()) return false;
        std::vector<std::uint8_t> hash = Pbkdf2Sha256(password, salt, iterations, 32);
        if (hash.empty()) return false;

        if (!WriteIniString(iniPath, L"Auth", L"AuthTokenSaltHex", BytesToHex(salt))) return false;
        if (!WriteIniString(iniPath, L"Auth", L"AuthTokenHashHex", BytesToHex(hash))) return false;
        if (!WriteIniString(iniPath, L"Auth", L"AuthTokenIterations", std::to_wstring(iterations))) return false;
        return true;
    }
}


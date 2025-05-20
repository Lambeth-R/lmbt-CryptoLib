#include <algorithm>
#include <functional>
#include <regex>
#include <string>
#include <vector>

#include <Windows.h>
#include <wincrypt.h>

#include "../Include/Cypher.h"
#include "../Include/Common.h"
#include "../Include/LogLib.h"

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

#pragma region AES

static bool AES_EncryptEx(HCRYPTKEY &hKey, void *ptr, size_t size, std::vector<uint8_t> &oData)
{
    bool res = false;
    DWORD data_len = static_cast<DWORD>(size);
    DWORD dw_ret_sz = data_len;
    oData.resize(size);
    memcpy(oData.data(), ptr, size);
    do
    {
        IF_NOT_CND_BREAK(CryptEncrypt(hKey, NULL, TRUE, 0, NULL, &dw_ret_sz, 0), res);

        oData.resize(dw_ret_sz);

        IF_NOT_CND_BREAK(CryptEncrypt(hKey, NULL, TRUE, 0, oData.data(), &data_len, static_cast<DWORD>(oData.size())), res);

    } while (false);
    if (!res)
    {
        Log_Error(L"Failed to encrypt string:", ParseLastError());
        oData.clear();
    }
    return res;
}

static bool AES_DecryptEx(HCRYPTKEY &hKey, void* ptr, size_t size, std::vector<uint8_t> &oData)
{
    HCRYPTPROV prov_context = 0;
    HCRYPTKEY  crypt_key = 0;
    MakeScopeGuard([&]() {
        if (prov_context)
        {
            CryptReleaseContext(prov_context, 0);
            prov_context = 0;
        }});
    MakeScopeGuard([&]() {
        if (crypt_key)
        {
            CryptDestroyKey(crypt_key);
            crypt_key = 0;
        }
        });
    bool res = true;
    DWORD dw_ret_sz = static_cast<DWORD>(size);
    oData.resize(size);
    memcpy(oData.data(), ptr, size);
    do
    {
        IF_NOT_CND_BREAK(CryptDecrypt(hKey, NULL, TRUE, 0, (BYTE*)oData.data(), &dw_ret_sz), res);

        oData.resize(dw_ret_sz);

    } while (false);
    if (!res)
    {
        Log_Error(L"Failed to decrypt string:", ParseLastError());
        oData.clear();
    }
    return res;
}

bool AES::InitContext(HCRYPTPROV &provider, HCRYPTKEY &key) const
{
    bool res = true;
    AES256KEYBLOB AESBlob;
    AESBlob.bhHdr.bType = PLAINTEXTKEYBLOB;
    AESBlob.bhHdr.bVersion = CUR_BLOB_VERSION;
    AESBlob.bhHdr.reserved = 0;
    AESBlob.bhHdr.aiKeyAlg = CALG_AES_256;
    AESBlob.dwKeySize = static_cast<DWORD>(m_Key.size());
    memcpy((void*)AESBlob.szBytes, (void*)m_Key.data(), AESBlob.dwKeySize);
    do
    {
        IF_NOT_CND_BREAK(CryptAcquireContextA(&provider, NULL, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_VERIFYCONTEXT), res);

        IF_NOT_CND_BREAK(CryptImportKey(provider, (BYTE*)&AESBlob, sizeof(AES256KEYBLOB), NULL, CRYPT_EXPORTABLE, &key), res);

        IF_NOT_CND_BREAK(CryptSetKeyParam(key, KP_IV, (BYTE*)m_IV.data(), 0), res);
    } while (false);
    if (!res)
    {
        Logstream_Error("Failed to init crypto context: " << ParseLastError());
    }
    return !res;
}

AES::AES(const AES &rhs)
{
    *this = rhs;
};

AES &AES::operator= (const AES &rhs)
{
    std::copy(std::begin(rhs.m_Key), std::end(rhs.m_Key), std::begin(m_Key));
    std::copy(std::begin(rhs.m_IV), std::end(rhs.m_IV), std::begin(m_IV));
    return *this;
}

bool AES::EncryptInPlace(std::vector<uint8_t> &iData) const
{
    std::vector<uint8_t> result_data;
    HCRYPTPROV prov_context = 0;
    HCRYPTKEY  crypt_key = 0;
    MakeScopeGuard([&]() {
        if (prov_context)
        {
            CryptReleaseContext(prov_context, 0);
            prov_context = 0;
        }});
    MakeScopeGuard([&]() {
        if (crypt_key)
        {
            CryptDestroyKey(crypt_key);
            crypt_key = 0;
        }
        });
    bool res = true;
    do
    {
        IF_NOT_CND_BREAK(InitContext(prov_context, crypt_key), res);

        IF_NOT_CND_BREAK(AES_EncryptEx(crypt_key, iData.data(), iData.size(), result_data), res);

    } while (false);
    if (res)
    {
        iData = result_data;
    }
    return res;
}

bool AES::EncryptInPlace(std::string &iData) const
{
    std::vector<uint8_t> result_data;
    HCRYPTPROV prov_context = 0;
    HCRYPTKEY  crypt_key = 0;
    MakeScopeGuard([&]() {
        if (prov_context)
        {
            CryptReleaseContext(prov_context, 0);
            prov_context = 0;
        }});
    MakeScopeGuard([&]() {
        if (crypt_key)
        {
            CryptDestroyKey(crypt_key);
            crypt_key = 0;
        }
        });
    bool res = true;
    do
    {
        IF_NOT_CND_BREAK(InitContext(prov_context, crypt_key), res);

        IF_NOT_CND_BREAK(AES_EncryptEx(crypt_key, iData.data(), iData.size(), result_data), res);

    } while (false);
    if (res)
    {
        iData = {result_data.begin(), result_data.end()};
    }
    return res;
}

bool AES::DecryptInPlace(std::vector<uint8_t> &iData) const
{
    std::vector<uint8_t> result_data;
    HCRYPTPROV  prov_context = 0;
    HCRYPTKEY   crypt_key = 0;
    bool res = true;
    MakeScopeGuard([&]() {
        if (prov_context)
        {
            CryptReleaseContext(prov_context, 0);
            prov_context = 0;
        }});
    MakeScopeGuard([&]() {
        if (crypt_key)
        {
            CryptDestroyKey(crypt_key);
            crypt_key = 0;
        }
        });
    do
    {
        IF_NOT_CND_BREAK(InitContext(prov_context, crypt_key), res);

        IF_NOT_CND_BREAK(AES_DecryptEx(crypt_key, iData.data(), iData.size(), result_data), res);

    } while (false);
    if (res)
    {
        iData = result_data;
    }
    return true;
}

bool AES::DecryptInPlace(std::string &iData) const
{
    std::vector<uint8_t> result_data;
    HCRYPTPROV  prov_context = 0;
    HCRYPTKEY   crypt_key = 0;
    bool res = true;
    MakeScopeGuard([&]() {
        if (prov_context)
        {
            CryptReleaseContext(prov_context, 0);
            prov_context = 0;
        }});
    MakeScopeGuard([&]() {
        if (crypt_key)
        {
            CryptDestroyKey(crypt_key);
            crypt_key = 0;
        }
        });
    do
    {
        IF_NOT_CND_BREAK(InitContext(prov_context, crypt_key), res);

        IF_NOT_CND_BREAK(AES_DecryptEx(crypt_key, iData.data(), iData.size(), result_data), res);

    } while (false);
    if (res)
    {
        iData = { result_data.begin(), result_data.end() };
    }
    return true;
}

bool AES::ImportKeys(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv)
{
    std::array<char, 32> keyArr;
    std::array<char, 16> ivArr;
    std::fill(m_Key.begin(), m_Key.end(), 0x00);
    std::fill(m_IV.begin(), m_IV.end(), 0x00);
    if (key.size() / 2 != 32 || iv.size() / 2 != 16 || !std::all_of(key.begin(), key.end(),
        [](char ch) {return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'); }))
    {
        return false;
    }
    auto keyLen = static_cast<DWORD>(key.size());
    auto ivLen = static_cast<DWORD>(iv.size());

    if (!CryptStringToBinaryA((const char*) key.data(), static_cast<DWORD>(key.size()), CRYPT_STRING_HEXRAW, (BYTE*)keyArr.data(), &keyLen, NULL, NULL) ||
        !CryptStringToBinaryA((const char*) iv.data(), static_cast<DWORD>(iv.size()), CRYPT_STRING_HEXRAW, (BYTE*)ivArr.data(), &ivLen, NULL, NULL))
    {
        Logstream_Error(__FUNCTION__ << " failed with" << ParseLastError());
        return false;
    }

    std::copy(keyArr.begin(), keyArr.begin() + keyLen, m_Key.data());
    std::copy(ivArr.begin(), ivArr.begin() + ivLen, m_IV.data());
    return true;
}

template <typename T>
bool AES::ExportKeys(T &key, T &iv) const
{
    if (m_Key.empty() || m_IV.empty())
    {
        return false;
    }
    key = { m_Key.begin(), m_Key.begin() + m_Key.size() };
    iv = { m_IV.begin(), m_IV.begin() + m_IV.size() };
    return true;
}

#pragma endregion

BCRYPT_ALG_HANDLE BaseCNG::InitAlgorithm(const wchar_t* alg)
{
    BCRYPT_ALG_HANDLE h_alg;
    auto st = BCryptOpenAlgorithmProvider(&h_alg, alg, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (st < 0)
    {
        st = BCryptOpenAlgorithmProvider(&h_alg, alg, MS_PRIMITIVE_PROVIDER, 0);
        if (st < 0)
        {
            Log_Error(L"Failed to init cryptoprovider");
            h_alg = nullptr;
        }
    }
    return h_alg;
}

bool BaseCNG::FillBufferRNG(size_t iLen, std::vector<uint8_t> &oData)
{
    bool res = true;
    NTSTATUS st = 0;
    do
    {
        oData.resize(iLen);
        st = BCryptGenRandom(nullptr, oData.data(), static_cast<ULONG>(iLen), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        IF_NOT_CND_BREAK(NT_SUCCESS(st), res);
    }
    while (false);
    if (!res)
    {
        oData.clear();
        Logstream_Error(L"Failed to generate random string: " << ParseLastError());
    }
    return res;
}

std::vector<uint8_t> BaseCNG::CalculateBase64(const std::vector<uint8_t> &iData)
{
    bool res = true;
    NTSTATUS st = 0;
    std::vector<uint8_t> result;
    DWORD o_size = 0;
    do
    {
        IF_NOT_CND_BREAK((CryptBinaryToStringA(iData.data(), static_cast<DWORD>(iData.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &o_size) == TRUE), res); // not exactly NTSTATUS

        result.resize(o_size);

        IF_NOT_CND_BREAK((CryptBinaryToStringA(iData.data(), static_cast<DWORD>(iData.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, (char*)result.data(), &o_size) == TRUE), res);

        result.resize(o_size);
    }
    while (false);
    if (!res)
    {
        result = {};
        Logstream_Error(L"Failed to calculate base64: " << ParseLastError());
    }
    return result;
}

#pragma region RSA

bool RSA::PEM_Encode(KeyType type, std::vector<uint8_t> &data)
{
    std::string formatted_prefix  = std::string(c_PemAddition) + c_PemBegin;
    std::string formatted_postfix = std::string(c_PemAddition) + c_PemEnd;

    if (!ValidKeyType(type))
    {
        return false;
    }
    else if (type  &RSA::KeyType_Public)
    {
        formatted_prefix  += std::string(" ") + c_PublicKeyId;
        formatted_postfix += std::string(" ") + c_PublicKeyId;
    }
    else if (type  &RSA::KeyType_Full)
    {
        formatted_prefix  += std::string(" ") + c_PrivateKeyId;
        formatted_postfix += std::string(" ") + c_PrivateKeyId;
    }
    else
    {
        return false;
    }

    formatted_prefix  += c_PemAddition;
    formatted_postfix += c_PemAddition;

    auto based_key = CalculateBase64(data);
    if (based_key.empty())
    {
        return false;
    }
    data.clear();
    data.insert(data.end(), formatted_prefix.begin(), formatted_prefix.end());
    for (size_t i = 0; i < based_key.size(); i += 64)
    {
        const auto &it = based_key.begin() + i;
        data.insert(data.end(), { 0x0A });
        data.insert(data.end(), it, it + std::min(64ull, based_key.size() - i));
    }
    data.insert(data.end(), { 0x0A });
    data.insert(data.end(), formatted_postfix.begin(), formatted_postfix.end());
    data.shrink_to_fit();
    return true;
}

bool RSA::PEM_Decode(KeyType type, std::vector<uint8_t> &data)
{
    std::string prefix_str = std::string(c_PemAddition) + c_PemBegin;
    prefix_str += std::string(".*") + c_PemAddition;
    std::regex formatted_prefix_reg(prefix_str);
    const std::string &str_data = { data.begin(), data.end() };
    std::smatch s_match;
    if (std::regex_match(str_data, s_match, formatted_prefix_reg))
    {
        int i = 1;
        i = 0;
    }
    return true;
}

RSA::~RSA()
{
    ReleaseKeyPair();
}

const RSA::KeyParams RSA::FillParams(KeyType type) const
{
    KeyParams params = {};
    if (!ValidKeyType(type))
    {
        return params;
    }
    else if (type  &KeyType_Public)
    {
        params.BlobType   = BCRYPT_RSAPUBLIC_BLOB;
        params.StructType = CNG_RSA_PUBLIC_KEY_BLOB;
    }
    else if (type  &KeyType_Full)
    {
        params.BlobType   = BCRYPT_RSAFULLPRIVATE_BLOB;
        params.StructType = CNG_RSA_PRIVATE_KEY_BLOB;
    }
    return params;
}

bool RSA::GenerateKeyPair(uint16_t keySize)
{
    if (m_KeyHandle)
    {
        Logstream_Error(L"Another keypair is allocated, release first.");
        return false;
    }
    BCRYPT_ALG_HANDLE h_alg = nullptr;
    MakeScopeGuard([=]() {if (h_alg) { BCryptCloseAlgorithmProvider(h_alg, 0); }});
    bool res     = true;
    NTSTATUS st  = 0;
    DWORD o_size = 0;
    do
    {
        h_alg = InitAlgorithm(BCRYPT_RSA_ALGORITHM);
        IF_NOT_CND_BREAK(h_alg, res);

        st = BCryptGenerateKeyPair(h_alg, &m_KeyHandle, keySize, 0);
        IF_NOT_CND_BREAK(NT_SUCCESS(st), res);

        st = BCryptFinalizeKeyPair(m_KeyHandle, 0);
        IF_NOT_CND_BREAK(NT_SUCCESS(st), res);

        m_Keytype = KeyType_Full;

    } while (false);
    if (!res)
    {
        Logstream_Error(L"Failed to generate key: " << ParseLastError());
    }

    return res;
}

bool RSA::ImportKeyInfo(KeyType type, const std::vector<uint8_t> &keyData)
{
    if (keyData.empty() || !ValidKeyType(type))
    {
        return false;
    }
    BCRYPT_ALG_HANDLE h_alg = nullptr;
    BCRYPT_KEY_HANDLE h_key = nullptr;
    MakeScopeGuard([=]() {if (h_alg) { BCryptCloseAlgorithmProvider(h_alg, 0); }});
    bool res = true;
    NTSTATUS st = 0;
    DWORD o_size = 0;

    const KeyParams &params = FillParams(type);
    std::vector<uint8_t> decoded_key = keyData;
    do
    {
        if (ValidKeyType(m_Keytype) && (m_Keytype & KeyType_PEM))
        {
            IF_NOT_CND_BREAK(PEM_Decode(type, decoded_key), res);
        }


        h_alg = InitAlgorithm(BCRYPT_RSA_ALGORITHM);
        IF_NOT_CND_BREAK(h_alg, res);

        IF_NOT_CND_BREAK(CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, params.StructType, (const BYTE *) decoded_key.data(), static_cast<DWORD>(decoded_key.size()), CRYPT_DECODE_NOCOPY_FLAG, nullptr, &o_size), res);

        auto blob_data = std::unique_ptr<uint8_t>(new uint8_t[o_size]);
        IF_NOT_CND_BREAK(CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, params.StructType, (const BYTE *) decoded_key.data(), static_cast<DWORD>(decoded_key.size()), CRYPT_DECODE_NOCOPY_FLAG, blob_data.get(), &o_size), res);

        st = BCryptImportKeyPair(h_alg, nullptr, params.BlobType, &h_key, (uint8_t*)blob_data.get(), o_size, 0);
        IF_NOT_CND_BREAK(NT_SUCCESS(st), res);

        m_Keytype = type;

    } while (false);
    if (!res)
    {
        Logstream_Error(L"Failed to export key: " << ParseLastError());
    }
    return res;
}

bool RSA::ExportKeyInfo(KeyType type, std::vector<uint8_t> &keyData)
{
    if (!ValidKeyType(m_Keytype  &type))
    {
        return false;
    }
    bool res = true;
    NTSTATUS st = 0;
    DWORD o_size = 0;
    const KeyParams &params = FillParams(type);

    do
    {
        st = BCryptExportKey(m_KeyHandle, nullptr, params.BlobType, nullptr, 0, &o_size, 0);
        IF_NOT_CND_BREAK(NT_SUCCESS(st), res);

        auto key_data = std::unique_ptr<uint8_t>(new uint8_t[o_size]);
        st = BCryptExportKey(m_KeyHandle, nullptr, params.BlobType, key_data.get(), o_size, &o_size, 0);
        IF_NOT_CND_BREAK(NT_SUCCESS(st), res);

        IF_NOT_CND_BREAK(CryptEncodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, params.StructType, key_data.get(), nullptr, &o_size), res);

        keyData.resize(o_size);
        IF_NOT_CND_BREAK(CryptEncodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, params.StructType, key_data.get(), reinterpret_cast<BYTE*>(keyData.data()), &o_size), res);
        break;
    } while (false);
    if (!res)
    {
        Logstream_Error(L"Failed to export key: " << ParseLastError());
        keyData.clear();
    }
    if (ValidKeyType(m_Keytype) && type & KeyType_PEM)
    {
        PEM_Encode(type, keyData);
    }
    return res;
}

bool RSA::Encrypt(const std::vector<uint8_t> &iString, std::vector<uint8_t> &oString) const
{
    if (!m_KeyHandle || (m_Keytype  &KeyType_Undefined) || iString.empty())
    {
        return false;
    }
    bool res     = true;
    NTSTATUS st  = 0;
    DWORD o_size = 0;
    oString.clear();
    do
    {
        st = BCryptEncrypt(m_KeyHandle, const_cast<uint8_t*>(iString.data()), static_cast<ULONG>(iString.size()), 
            m_ExplicitPadding ? (void*)&c_PaddingInfo : nullptr, nullptr, 0, nullptr,
            0, &o_size, m_ExplicitPadding ? BCRYPT_PAD_OAEP : BCRYPT_PAD_NONE);

        IF_NOT_CND_BREAK(NT_SUCCESS(st), res);

        std::vector<uint8_t> aligned_data = iString;
        aligned_data.resize(o_size);
        if (!m_ExplicitPadding)
        {
            oString.resize(o_size);
        }

        st = BCryptEncrypt(m_KeyHandle, (uint8_t*)aligned_data.data(), static_cast<ULONG>(aligned_data.size()), 
            m_ExplicitPadding ? (void*)&c_PaddingInfo : nullptr, nullptr, 0, reinterpret_cast<uint8_t*>(oString.data()),
            static_cast<ULONG>(oString.size()), &o_size, m_ExplicitPadding ? BCRYPT_PAD_OAEP : BCRYPT_PAD_NONE);
        IF_NOT_CND_BREAK(NT_SUCCESS(st), res);

    } while (false);
    if (!res)
    {
        oString.clear();
    }
    return res;
};

bool RSA::Decrypt(const std::vector<uint8_t> &iString, std::vector<uint8_t> &oString) const
{
    if (!m_KeyHandle || (m_Keytype  &KeyType_Undefined || m_Keytype  &KeyType_Public) || iString.empty())
    {
        return false;
    }
    bool res     = true;
    NTSTATUS st  = 0;
    DWORD o_size = 0;
    oString.clear();
    do
    {
        st = BCryptDecrypt(m_KeyHandle, (uint8_t*)iString.data(), static_cast<ULONG>(iString.size()), 
            m_ExplicitPadding ? (void*)&c_PaddingInfo : nullptr, nullptr, 0, nullptr, 0, &o_size,
            m_ExplicitPadding ? BCRYPT_PAD_OAEP : BCRYPT_PAD_NONE);
        IF_NOT_CND_BREAK(NT_SUCCESS(st), res);

        oString.resize(o_size);

        st = BCryptDecrypt(m_KeyHandle, (uint8_t*)iString.data(), static_cast<ULONG>(iString.size()),
            m_ExplicitPadding ? (void*)&c_PaddingInfo : nullptr, nullptr, 0, reinterpret_cast<uint8_t*>(oString.data()),
            static_cast<ULONG>(oString.size()), &o_size, m_ExplicitPadding ? BCRYPT_PAD_OAEP : BCRYPT_PAD_NONE);
        IF_NOT_CND_BREAK(NT_SUCCESS(st), res);

    } while (false);
    if (!res)
    {
        oString.clear();
    }
    return res;
};

void RSA::ReleaseKeyPair()
{
    if (m_KeyHandle)
    {
        BCryptDestroyKey(m_KeyHandle);
        m_KeyHandle = nullptr;
        m_Keytype   = KeyType_Undefined;
    }
}

#pragma endregion

#pragma region Hash

Hash::Hash(InnerHashType extenrT) : m_ExternType(extenrT) {}

Hash::Hash(const wchar_t* alg) : m_AlgHandle(InitAlgorithm(alg)) {}

Hash::~Hash() {
    if (m_AlgHandle) { BCryptCloseAlgorithmProvider(m_AlgHandle, 0); }}

const Hash Hash::SHA_1()
{
    return Hash(BCRYPT_SHA1_ALGORITHM);
}

const Hash Hash::SHA_256()
{
    return Hash(BCRYPT_SHA256_ALGORITHM);
}

const Hash Hash::SHA_384()
{
    return Hash(BCRYPT_SHA384_ALGORITHM);
}

const Hash Hash::SHA_512()
{
    return Hash(BCRYPT_SHA512_ALGORITHM);
}

const Hash Hash::MD2()
{
    return Hash(BCRYPT_MD2_ALGORITHM);
}

const Hash Hash::MD4()
{
    return Hash(BCRYPT_MD4_ALGORITHM);
}

const Hash Hash::MD5()
{
    return Hash(BCRYPT_MD5_ALGORITHM);
}

const Hash Hash::Crc32()
{
    return Hash(Hash_Crc32);
}

static uint32_t ComputeCrc32(const std::vector<uint8_t> &iData)
{
    typedef uint32_t (__stdcall *t_RtlComputeCrc32)(int, const uint8_t*, uint32_t);
    t_RtlComputeCrc32 crc32Calc = nullptr;
    HMODULE hDLL = nullptr;
    bool res = true;
    do
    {
        IF_NOT_CND_BREAK(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"ntdll.dll", &hDLL), res);

        crc32Calc = (t_RtlComputeCrc32)GetProcAddress(hDLL, "RtlComputeCrc32");
        IF_NOT_CND_BREAK(crc32Calc, res);

    } while (false);
    if (!res)
    {
        return 0;
    }
    return crc32Calc(0, iData.data(), static_cast<uint32_t>(iData.size()));
}

const std::vector<uint8_t> Hash::InnerHash(const std::vector<uint8_t> &iData) const
{
    std::vector<uint8_t> out_hash;
    switch (m_ExternType)
    {
        case Hash_Crc32:
        {
            uint32_t crc32 = ComputeCrc32(iData);
            while (crc32)
            {
                out_hash.push_back(crc32  &0xFF);
                crc32 >>= 8;
            }
            return { out_hash.rbegin(), out_hash.rend() };
        }
        case Hash_Undefined:
        default:
            Logstream_Error(L"Unimplemented.");
            return {};
    }
}

const std::vector<uint8_t> Hash::CalculateHash(const std::vector<uint8_t> &iData, const std::vector<uint8_t> &iSalt) const
{
    if (m_ExternType != Hash_Undefined)
    {
        return InnerHash(iData);
    }
    else
    {
        std::vector<uint8_t> out_hash;
        ULONG o_size = 0;
        DWORD hash_len = 0;
        NTSTATUS st = 0;
        bool res = true;
        do
        {
            IF_NOT_CND_BREAK(m_AlgHandle, res);

            st = BCryptGetProperty(m_AlgHandle, BCRYPT_HASH_LENGTH, (uint8_t*)&hash_len, sizeof(DWORD), &o_size, 0);
            IF_NOT_CND_BREAK(NT_SUCCESS(st) || !o_size || !hash_len, res);

            out_hash.resize(hash_len);

            std::vector<uint8_t> merged_data = iData;
            if (!iSalt.empty())
            {
                merged_data.insert(merged_data.end(), iSalt.begin(), iSalt.end());
            }

            st = BCryptHash(m_AlgHandle, nullptr, 0, const_cast<uint8_t*>(iData.data()), static_cast<ULONG>(iData.size()), out_hash.data(), static_cast<ULONG>(out_hash.size()));
            IF_NOT_CND_BREAK(NT_SUCCESS(st), res);
        } while (false);
        if (!res)
        {
            Logstream_Error(L"Failed to calculate hash.");
            out_hash.clear();
        }
        return out_hash;
    }
}

bool Hash::VerifyHashData(const std::vector<uint8_t> &hashData, const std::vector<uint8_t> &iData, const std::vector<uint8_t> &iSalt) const
{
    const auto &recalc_hash = CalculateHash(iData, iSalt);
    return hashData.size() == recalc_hash.size() && std::memcmp(hashData.data(), recalc_hash.data(), hashData.size()) == 0;
}

#pragma endregion
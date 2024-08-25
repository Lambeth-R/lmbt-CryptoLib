#define MODULE_NAME L"Cypher"
#include <algorithm>
#include <functional>

#include <Windows.h>
#include <wincrypt.h>

#include "../Include/Cypher.h"
#include "../Include/Common.h"
#include "../Include/LogClass.h"

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

#pragma region AES

bool AES::InitContext(HCRYPTPROV& provider, HCRYPTKEY& key) const
{
    bool err = false;
    AES256KEYBLOB AESBlob;
    AESBlob.bhHdr.bType = PLAINTEXTKEYBLOB;
    AESBlob.bhHdr.bVersion = CUR_BLOB_VERSION;
    AESBlob.bhHdr.reserved = 0;
    AESBlob.bhHdr.aiKeyAlg = CALG_AES_256;
    AESBlob.dwKeySize = static_cast<DWORD>(m_Key.size());
    memcpy((void*)AESBlob.szBytes, (void*)m_Key.data(), AESBlob.dwKeySize);
    do
    {
        if (!CryptAcquireContextA(&provider, NULL, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        {
            Logstream_Error("CryptAcquireContextA failed with: " << ParseLastError());
            err = true;
            break;
        }

        if (!CryptImportKey(provider, (BYTE*)&AESBlob, sizeof(AES256KEYBLOB), NULL, CRYPT_EXPORTABLE, &key))
        {
            Logstream_Error("CryptImportKey failed with: " << ParseLastError());
            err = true;
            break;
        }
        if (!CryptSetKeyParam(key, KP_IV, (BYTE*)m_IV.data(), 0))
        {
            Logstream_Error("CryptSetKeyParam failed with: " << ParseLastError());
            err = true;
            break;
        }
    } while (false);
    return err;
}

AES::AES(const AES& rhs)
{
    *this = rhs;
};

AES& AES::operator= (const AES& rhs)
{
    std::copy(std::begin(rhs.m_Key), std::end(rhs.m_Key), std::begin(m_Key));
    std::copy(std::begin(rhs.m_IV), std::end(rhs.m_IV), std::begin(m_IV));
    return *this;
}

bool AES::EncryptInPlace(std::vector<uint8_t> &iString) const
{
    HCRYPTPROV pHCRYPT = NULL;
    HCRYPTKEY pHKey = NULL;
    bool err = false;
    DWORD data_len = (DWORD)iString.size();
    DWORD dw_ret_sz = data_len;
    MakeScopeGuard([&]() {
        if (pHCRYPT)
        {
            CryptReleaseContext(pHCRYPT, 0);
            pHCRYPT = 0;
        }
        if (pHKey)
        {
            CryptDestroyKey(pHKey);
            pHKey = 0;
        }
    });
    do {
        err = InitContext(pHCRYPT, pHKey);
        if (err)
        {
            break;
        }

        if (!CryptEncrypt(pHKey, NULL, TRUE, 0, NULL, &dw_ret_sz, 0))
        {
            Logstream_Error("First CryptEncrypt failed with: " << ParseLastError());
            err = true;
            break;
        }
        iString.resize(dw_ret_sz);
        if (!CryptEncrypt(pHKey, NULL, TRUE, 0, iString.data(), &data_len, static_cast<DWORD>(iString.size())))
        {
            Logstream_Error("Second CryptEncrypt failed with: " << ParseLastError());
            err = true;
            break;
        }
    } while (false);

    if (pHKey)
    {
        CryptDestroyKey(pHKey);
        pHKey = 0;
    }
    if (pHCRYPT)
    {
        CryptReleaseContext(pHCRYPT, 0);
        pHCRYPT = 0;
    }
    return err;
}

bool AES::DecryptInPlace(std::vector<uint8_t> &iString) const
{
    HCRYPTPROV pHCRYPT = NULL;
    HCRYPTKEY pHKey = NULL;
    bool err = false;
    DWORD stringLen = static_cast<DWORD>(iString.size());
    MakeScopeGuard([&]() {
        if (pHCRYPT)
        {
            CryptReleaseContext(pHCRYPT, 0);
            pHCRYPT = 0;
        }
        if (pHKey)
        {
            CryptDestroyKey(pHKey);
            pHKey = 0;
        }
    });
    do
    {
        err = InitContext(pHCRYPT, pHKey);
        if (err)
        {
            break;
        }
        if (!CryptDecrypt(pHKey, NULL, TRUE, 0, (BYTE*)iString.data(), &stringLen))
        {
            Logstream_Error("CryptDecrypt failed with: " << ParseLastError());
            err = true;
            break;
        }
        iString.resize(stringLen);
    } while (false);
    if (pHKey)
    {
        CryptDestroyKey(pHKey);
        pHKey = 0;
    }
    if (pHCRYPT)
    {
        CryptReleaseContext(pHCRYPT, 0);
        pHCRYPT = 0;
    }
    return true;
}

bool AES::Encrypt(const std::vector<uint8_t>& iString, std::vector<uint8_t> &oString) const
{
    oString = iString;
    return EncryptInPlace(oString);
}

bool AES::Decrypt(const std::vector<uint8_t> &iString, std::vector<uint8_t> &oString) const
{
    oString = iString;
    return DecryptInPlace(oString);
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

bool AES::ExportKeys(std::vector<uint8_t> &key, std::vector<uint8_t> &iv) const
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

#pragma region RSA

BCRYPT_ALG_HANDLE RSA::InitAlgorithm()
{
    BCRYPT_ALG_HANDLE h_alg;
    auto st = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_RSA_ALGORITHM, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (st < 0)
    {
        st = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_RSA_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
        if (st < 0)
        {
            Log_Error(L"Failed to init cryptoprovider");
            h_alg = nullptr;
        }
    }
    return h_alg;
}

RSA::~RSA()
{
    ReleaseKeyPair();
}

constexpr RSA::KeyParams RSA::FillParams(KeyType type) const
{
    KeyParams params = {};
    switch (type)
    {
    case KeyType_Public:
    {
        params.BlobType = BCRYPT_RSAPUBLIC_BLOB;
        params.StructType = CNG_RSA_PUBLIC_KEY_BLOB;
        break;
    }
    case KeyType_Full:
    {
        params.BlobType = BCRYPT_RSAFULLPRIVATE_BLOB;
        params.StructType = CNG_RSA_PRIVATE_KEY_BLOB;
        break;
    }
    case KeyType_Undefined:
    default:
        break;
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
        h_alg = InitAlgorithm();
        if (!h_alg)
        {
            res = false;
            break;
        }
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
    if (keyData.empty() || type == KeyType_Undefined)
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

    do
    {
        h_alg = InitAlgorithm();
        if (!h_alg)
        {
            res = false;
            break;
        }

        IF_NOT_CND_BREAK(CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, params.StructType, (const BYTE *)keyData.data(), keyData.size(), CRYPT_DECODE_NOCOPY_FLAG, nullptr, &o_size), res);

        auto blob_data = std::unique_ptr<uint8_t>(new uint8_t[o_size]);
        IF_NOT_CND_BREAK(CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, params.StructType, (const BYTE*)keyData.data(), keyData.size(), CRYPT_DECODE_NOCOPY_FLAG, blob_data.get(), &o_size), res);

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
    if (m_Keytype < type)
    {
        return false;
    }
    bool res = true;
    NTSTATUS st = 0;
    DWORD o_size = 0;
    const KeyParams& params = FillParams(type);

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
    return res;
}

bool RSA::Encrypt(const std::vector<uint8_t> &iString, std::vector<uint8_t> &oString) const
{
    if (!m_KeyHandle || m_Keytype < KeyType_Public || iString.empty())
    {
        return false;
    }
    bool res     = true;
    NTSTATUS st  = 0;
    DWORD o_size = 0;
    oString.clear();
    do
    {
        st = BCryptEncrypt(m_KeyHandle, const_cast<uint8_t*>(iString.data()), iString.size(), 
            m_ExplicitPadding ? (void*)&c_PaddingInfo : nullptr, nullptr, 0, nullptr,
            0, &o_size, m_ExplicitPadding ? BCRYPT_PAD_OAEP : BCRYPT_PAD_NONE);

        IF_NOT_CND_BREAK(NT_SUCCESS(st), res);

        std::vector<uint8_t> aligned_data = iString;
        aligned_data.resize(o_size);
        if (!m_ExplicitPadding)
        {
            oString.resize(o_size);
        }

        st = BCryptEncrypt(m_KeyHandle, (uint8_t*)aligned_data.data(), aligned_data.size(), 
            m_ExplicitPadding ? (void*)&c_PaddingInfo : nullptr, nullptr, 0, reinterpret_cast<uint8_t*>(oString.data()),
            oString.size(), &o_size, m_ExplicitPadding ? BCRYPT_PAD_OAEP : BCRYPT_PAD_NONE);
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
    if (!m_KeyHandle || m_Keytype < KeyType_Full || iString.empty())
    {
        return false;
    }
    bool res     = true;
    NTSTATUS st  = 0;
    DWORD o_size = 0;
    oString.clear();
    do
    {
        st = BCryptDecrypt(m_KeyHandle, (uint8_t*)iString.data(), iString.size(), 
            m_ExplicitPadding ? (void*)&c_PaddingInfo : nullptr, nullptr, 0, nullptr, 0, &o_size,
            m_ExplicitPadding ? BCRYPT_PAD_OAEP : BCRYPT_PAD_NONE);
        IF_NOT_CND_BREAK(NT_SUCCESS(st), res);

        oString.resize(o_size);

        st = BCryptDecrypt(m_KeyHandle, (uint8_t*)iString.data(), iString.size(), 
            m_ExplicitPadding ? (void*)&c_PaddingInfo : nullptr, nullptr, 0, reinterpret_cast<uint8_t*>(oString.data()),
            oString.size(), &o_size, m_ExplicitPadding ? BCRYPT_PAD_OAEP : BCRYPT_PAD_NONE);
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
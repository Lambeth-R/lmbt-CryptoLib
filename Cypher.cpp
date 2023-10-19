#define MODULE_NAME "Cypher"
#include <algorithm>
#include <Windows.h>
#include <wincrypt.h>

#include "../Include/Cypher.h"
#include "../Include/Common.h"
#include "../Include/LogClass.h"
#include "../Include/UTF_Unocode.h"

#pragma comment(lib, "Crypt32.lib")

bool AES::InitContext(HCRYPTPROV& provider, HCRYPTKEY& key)
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
            LOG(eLogLevels::Error, "CryptAcquireContextA failed with: " << PARSE_ERROR(GetLastError()));
            err = true;
            break;
        }

        if (!CryptImportKey(provider, (BYTE*)&AESBlob, sizeof(AES256KEYBLOB), NULL, CRYPT_EXPORTABLE, &key))
        {
            LOG(eLogLevels::Error, "CryptImportKey failed with: " << PARSE_ERROR(GetLastError()));
            err = true;
            break;
        }
        if (!CryptSetKeyParam(key, KP_IV, (BYTE*)m_IV.data(), 0))
        {
            LOG(eLogLevels::Error, "CryptSetKeyParam failed with: " << PARSE_ERROR(GetLastError()));
            err = true;
            break;
        }
    } while (false);
    return err;
}

bool AES::EncryptInPlace(std::string& iString)
{
    HCRYPTPROV pHCRYPT = NULL;
    HCRYPTKEY pHKey = NULL;
    bool err = false;
    DWORD data_len = (DWORD)iString.length();
    DWORD dw_ret_sz = data_len;
    std::shared_ptr<void> _{nullptr, [&](void* ptr = nullptr) {
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
    }};
    do {
        err = InitContext(pHCRYPT, pHKey);
        if (err)
        {
            break;
        }

        if (!CryptEncrypt(pHKey, NULL, TRUE, 0, NULL, &dw_ret_sz, 0))
        {
            LOG(eLogLevels::Error, "First CryptEncrypt failed with: " << PARSE_ERROR(GetLastError()));
            err = true;
            break;
        }
        iString.resize(dw_ret_sz);
        if (!CryptEncrypt(pHKey, NULL, TRUE, 0, (BYTE*)iString.data(), &data_len, static_cast<DWORD>(iString.size())))
        {
            LOG(eLogLevels::Error, "Second CryptEncrypt failed with: " << PARSE_ERROR(GetLastError()));
            err = true;
            break;
        }
    } while (false);
    return err;
}

bool AES::DecryptInPlace(std::string& iString)
{
    HCRYPTPROV pHCRYPT = NULL;
    HCRYPTKEY pHKey = NULL;
    bool err = false;
    DWORD stringLen = static_cast<DWORD>(iString.size());
    std::shared_ptr<void> _{nullptr, [&](void* ptr = nullptr) {
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
    }};
    do
    {
        err = InitContext(pHCRYPT, pHKey);
        if (err)
        {
            break;
        }
        if (!CryptDecrypt(pHKey, NULL, TRUE, 0, (BYTE*)iString.data(), &stringLen))
        {
            LOG(eLogLevels::Error, "CryptDecrypt failed with: " << PARSE_ERROR(GetLastError()));
            err = true;
            break;
        }
        iString.resize(stringLen);
    } while (false);
    return true;
}

bool AES::ImportKeys(const std::string& key, const std::string& iv)
{
    std::array<char, 32> keyArr;
    std::array<char, 16> ivArr;
    std::fill(m_Key.begin(), m_Key.end(), 0x00);
    std::fill(m_IV.begin(), m_IV.end(), 0x00);
    if (key.length() / 2 != 32 || iv.length() / 2 != 16 || !std::all_of(key.begin(), key.end(),
        [](char ch) {return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'); }))
    {
        return false;
    }
    auto keyLen = static_cast<DWORD>(key.length());
    auto ivLen = static_cast<DWORD>(iv.length());

    if (!CryptStringToBinaryA(key.data(), static_cast<DWORD>(key.length()), CRYPT_STRING_HEXRAW, (BYTE*)keyArr.data(), &keyLen, NULL, NULL) ||
        !CryptStringToBinaryA(iv.data(), static_cast<DWORD>(iv.length()), CRYPT_STRING_HEXRAW, (BYTE*)ivArr.data(), &ivLen, NULL, NULL))
    {
        LOG(eLogLevels::Error, __FUNCTION__ << " failed with" << PARSE_ERROR(GetLastError()));
        return false;
    }

    std::copy(keyArr.begin(), keyArr.begin() + keyLen, m_Key.data());
    std::copy(ivArr.begin(), ivArr.begin() + ivLen, m_IV.data());
    return true;
}

bool AES::ExportKeys(std::string& key, std::string& iv)
{
    key.clear();
    key.append(32, '0');
    memcpy((void*)key.data(), (void*)m_Key.data(), m_Key.size());
    iv.clear();
    iv.append(16, '0');
    memcpy((void*)(iv.data()), (void*)m_IV.data(), m_IV.size());
    return false;
}
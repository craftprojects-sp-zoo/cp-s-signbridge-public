// SignBridge — © 2026 Craftprojects Sp. z o.o. (craftprojects.pl)
// cp-signbridge — certyfikat testowy z kluczem tylko w pamięci (nic nie zostaje w systemie); dane fikcyjne
#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <string>
#include <vector>

namespace t {

// Samopodpisany certyfikat „CN=<cn>”: RSA 2048 (ec=false) albo ECDSA P-256 (ec=true). Zwalnia wywołujący.
// Klucz efemeryczny (bez nazwy) u dostawcy programowego Windows — znika razem z uchwytem.
inline PCCERT_CONTEXT MakeTestCert(bool ec, const wchar_t* cn) {
    std::wstring subject = std::wstring(L"CN=") + cn;
    DWORD cbName = 0;
    if (!CertStrToNameW(X509_ASN_ENCODING, subject.c_str(), CERT_X500_NAME_STR, NULL, NULL, &cbName, NULL)) return NULL;
    std::vector<BYTE> name(cbName);
    if (!CertStrToNameW(X509_ASN_ENCODING, subject.c_str(), CERT_X500_NAME_STR, NULL, name.data(), &cbName, NULL)) return NULL;
    CERT_NAME_BLOB blob = { cbName, name.data() };
    CRYPT_ALGORITHM_IDENTIFIER alg = {};
    alg.pszObjId = (LPSTR)(ec ? szOID_ECDSA_SHA256 : szOID_RSA_SHA256RSA);
    PCCERT_CONTEXT cert = NULL;
    NCRYPT_PROV_HANDLE hp = 0; NCRYPT_KEY_HANDLE hk = 0;
    if (NCryptOpenStorageProvider(&hp, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) return NULL;
    if (NCryptCreatePersistedKey(hp, &hk, ec ? BCRYPT_ECDSA_P256_ALGORITHM : BCRYPT_RSA_ALGORITHM, NULL, 0, 0) == ERROR_SUCCESS) {
        DWORD bits = 2048;
        if (!ec) NCryptSetProperty(hk, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, sizeof(bits), 0);
        if (NCryptFinalizeKey(hk, 0) == ERROR_SUCCESS)
            cert = CertCreateSelfSignCertificate(hk, &blob, CERT_CREATE_SELFSIGN_NO_KEY_INFO, NULL, &alg, NULL, NULL, NULL);
        NCryptFreeObject(hk);
    }
    NCryptFreeObject(hp);
    return cert;
}

}  // namespace t

// SignBridge — © 2026 Craftprojects Sp. z o.o. (craftprojects.pl)
// cp-signbridge — skróty obsługiwane przy podpisie: identyfikator CAPI (ALG_ID), nazwa CNG, długość w bajtach.
// Jedno miejsce prawdy o długości skrótu: przed wysłaniem do podpisu sprawdzamy ją z tą tabelą.
#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>

namespace sb { namespace hashalg {

struct Info {
    ALG_ID algId;            // CALG_SHA_256 ...
    const wchar_t* cngName;  // BCRYPT_SHA256_ALGORITHM ... (ta nazwa idzie w protokole kanału jako hashAlg)
    DWORD bytes;             // długość skrótu
    const char* name;        // nazwa do wyliczania algorytmów dostawcy (PP_ENUMALGS)
    const char* longName;
};

inline const Info kAll[] = {
    { CALG_SHA_256, BCRYPT_SHA256_ALGORITHM, 32, "SHA-256", "Secure Hash Algorithm (SHA-256)" },
    { CALG_SHA_384, BCRYPT_SHA384_ALGORITHM, 48, "SHA-384", "Secure Hash Algorithm (SHA-384)" },
    { CALG_SHA_512, BCRYPT_SHA512_ALGORITHM, 64, "SHA-512", "Secure Hash Algorithm (SHA-512)" },
    { CALG_SHA1,    BCRYPT_SHA1_ALGORITHM,   20, "SHA-1",   "Secure Hash Algorithm (SHA-1)" },
};
const int kCount = (int)(sizeof(kAll) / sizeof(kAll[0]));

// nullptr = skrót nieobsługiwany (MD5, SSL3_SHAMD5, HMAC ...)
inline const Info* ByAlgId(ALG_ID alg) {
    for (const Info& i : kAll) if (i.algId == alg) return &i;
    return nullptr;
}

}}  // namespace sb::hashalg

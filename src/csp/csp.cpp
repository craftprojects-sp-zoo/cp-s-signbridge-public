// SignBridge — © 2026 Craftprojects Sp. z o.o. (craftprojects.pl)
// cp-signbridge — dostawca CryptoAPI (CSP), cpsignbridge-csp.dll
//
// Starsze programy (np. .NET Framework X509Certificate2.PrivateKey, Symfonia) pobierają klucz starym API
// (CAPI), które zna tylko dostawców CSP — przy certyfikacie przypiętym wyłącznie do KSP dostają
// NTE_BAD_PROV_TYPE („Invalid provider type specified”). Ta biblioteka jest cienką warstwą CAPI nad tym
// samym backendem co KSP: kontener = odcisk certyfikatu z magazynu Osobiste, a podpis idzie tą samą drogą
// (backend_remote -> agentclient -> kanał wirtualny RDP -> wtyczka mstsc). Drugiej ścieżki podpisu nie ma.
//
// Nazwa dostawcy: "SignBridge Cryptographic Provider", typ PROV_RSA_AES (24).
// Zakres: tylko RSA, podpis PKCS#1 v1.5, skróty SHA-256 / SHA-384 / SHA-512 / SHA-1. Bez tworzenia,
// importu i eksportu kluczy prywatnych, bez szyfrowania. CAPI podaje i odbiera podpis w kolejności
// little-endian (odwrotnie niż CNG i karta) — bajty odwracamy na granicy tej biblioteki.
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <string.h>
#include <string>
#include <vector>
#include <algorithm>
#include <new>
#include "csp.h"
#include "backend.h"
#include "log.h"
#include "../common/certs.h"
#include "../common/hashalg.h"
#include "../common/keyprov.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace {

using sb::hashalg::Info;

const DWORD kProvMagic = 0x50434253;  // 'SBCP'
const DWORD kKeyMagic  = 0x4B434253;  // 'SBCK'
const DWORD kHashMagic = 0x48434253;  // 'SBCH'
const DWORD kCspVersion = 0x0102;     // PP_VERSION: 1.2

struct ProvObj {
    DWORD magic;
    std::string provName;                 // PP_NAME
    std::wstring container;               // odcisk certyfikatu; pusty = kontekst bez klucza (CRYPT_VERIFYCONTEXT)
    sb::IKey* key;                        // nullptr w kontekście bez klucza
    std::vector<std::wstring> enumNames;  // stan PP_ENUMCONTAINERS
    size_t enumName;
    size_t enumAlg;                       // stan PP_ENUMALGS / PP_ENUMALGS_EX
};

struct KeyObj {
    DWORD magic;
    ProvObj* prov;
    DWORD keySpec;           // AT_SIGNATURE albo AT_KEYEXCHANGE — ten sam klucz z karty
    BCRYPT_KEY_HANDLE pub;   // klucz publiczny zaimportowany przez program (tylko do weryfikacji); NULL = klucz z karty
};

struct HashObj {
    DWORD magic;
    const Info* alg;
    BCRYPT_HASH_HANDLE h;
    bool done;                 // skrót policzony albo podany przez HP_HASHVAL — dalszych danych nie przyjmujemy
    std::vector<BYTE> value;
};

INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
sb::IBackend* g_backend = nullptr;
sb::IBackend* g_testBackend = nullptr;

BOOL CALLBACK InitOnce(PINIT_ONCE, PVOID, PVOID*) {
    sb::LogInit(L"csp");
#ifdef _WIN64
    const wchar_t* arch = L"x64";
#else
    const wchar_t* arch = L"x86";
#endif
    SB_INFO(L"=== CSP załadowany: proces '%s', użytkownik '%s', sesja %lu, %s",
            sb::ProcessName().c_str(), sb::UserName().c_str(), sb::SessionId(), arch);
    g_backend = sb::CreateCompositeBackend();
    return TRUE;
}

sb::IBackend* Backend() {
    InitOnceExecuteOnce(&g_once, InitOnce, NULL, NULL);
    return g_testBackend ? g_testBackend : g_backend;
}

BOOL Fail(DWORD e) { SetLastError(e); return FALSE; }

// Wynik o znanym rozmiarze — konwencja CAPI: pbData == NULL to pytanie o rozmiar, za mały bufor to ERROR_MORE_DATA
BOOL Out(LPBYTE pbData, LPDWORD pcbDataLen, const void* data, DWORD size) {
    if (!pcbDataLen) return Fail(ERROR_INVALID_PARAMETER);
    if (!pbData) { *pcbDataLen = size; return TRUE; }
    if (*pcbDataLen < size) { *pcbDataLen = size; return Fail(ERROR_MORE_DATA); }
    memcpy(pbData, data, size);
    *pcbDataLen = size;
    return TRUE;
}
BOOL OutDword(LPBYTE pbData, LPDWORD pcbDataLen, DWORD v) { return Out(pbData, pcbDataLen, &v, sizeof(v)); }
BOOL OutAnsi(LPBYTE pbData, LPDWORD pcbDataLen, const std::string& s) { return Out(pbData, pcbDataLen, s.c_str(), (DWORD)s.size() + 1); }

ProvObj* AsProv(HCRYPTPROV h) { ProvObj* p = (ProvObj*)h; return (p && p->magic == kProvMagic) ? p : nullptr; }
KeyObj* AsKey(HCRYPTKEY h) { KeyObj* k = (KeyObj*)h; return (k && k->magic == kKeyMagic && k->prov && k->prov->magic == kProvMagic) ? k : nullptr; }
HashObj* AsHash(HCRYPTHASH h) { HashObj* o = (HashObj*)h; return (o && o->magic == kHashMagic) ? o : nullptr; }

std::string ToAnsi(const std::wstring& w) {
    int n = WideCharToMultiByte(CP_ACP, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string s(n > 0 ? n : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_ACP, 0, w.c_str(), (int)w.size(), &s[0], n, NULL, NULL);
    return s;
}

// Nazwa kontenera od programu: odcisk certyfikatu; zapis kart inteligentnych "\\.\czytnik\kontener" — sam kontener
std::wstring ContainerName(LPCSTR sz) {
    if (!sz || !*sz) return L"";
    int n = MultiByteToWideChar(CP_ACP, 0, sz, -1, NULL, 0);
    std::wstring w(n > 0 ? n - 1 : 0, L'\0');
    if (n > 1) MultiByteToWideChar(CP_ACP, 0, sz, -1, &w[0], n);
    if (w.rfind(L"\\\\.\\", 0) == 0) w = w.substr(w.find_last_of(L'\\') + 1);
    return w;
}

bool IsRsa(sb::IKey* k) { return _wcsicmp(k->AlgGroup(), NCRYPT_RSA_ALGORITHM_GROUP) == 0; }
bool ValidKeySpec(DWORD spec) { return spec == AT_SIGNATURE || spec == AT_KEYEXCHANGE; }

// Kontenery, które ten dostawca umie obsłużyć: certyfikaty z komputera użytkownika z kluczem RSA
std::vector<std::wstring> RsaContainers() {
    std::vector<std::wstring> all, rsa;
    Backend()->Enumerate(all);
    for (const auto& n : all) {
        sb::IKey* k = nullptr;
        if (Backend()->Open(n, &k) != ERROR_SUCCESS || !k) continue;
        if (IsRsa(k)) rsa.push_back(n);
        delete k;
    }
    return rsa;
}

std::wstring Hex(const BYTE* p, size_t n, size_t maxBytes) {
    std::wstring s;
    wchar_t b[4];
    for (size_t i = 0; i < n && i < maxBytes; ++i) { swprintf_s(b, L"%02X", p[i]); s += b; }
    if (n > maxBytes) s += L"…";
    return s;
}

// Uchwyty algorytmów skrótu BCrypt: otwierane raz na proces i niezamykane (żyją dłużej niż obiekty skrótu)
SRWLOCK g_algLock = SRWLOCK_INIT;
BCRYPT_ALG_HANDLE g_algHandles[sb::hashalg::kCount] = {};

BCRYPT_ALG_HANDLE AlgHandle(const Info* a) {
    size_t i = (size_t)(a - sb::hashalg::kAll);
    AcquireSRWLockExclusive(&g_algLock);
    if (!g_algHandles[i] && !BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&g_algHandles[i], a->cngName, NULL, 0))) g_algHandles[i] = NULL;
    BCRYPT_ALG_HANDLE h = g_algHandles[i];
    ReleaseSRWLockExclusive(&g_algLock);
    return h;
}

BCRYPT_ALG_HANDLE g_rsaAlg = NULL;

BCRYPT_ALG_HANDLE RsaAlgHandle() {
    AcquireSRWLockExclusive(&g_algLock);
    if (!g_rsaAlg && !BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&g_rsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0))) g_rsaAlg = NULL;
    BCRYPT_ALG_HANDLE h = g_rsaAlg;
    ReleaseSRWLockExclusive(&g_algLock);
    return h;
}

// Klucz nadaje się do użycia: zaimportowany klucz publiczny albo klucz z karty w kontekście z kontenerem
bool Usable(KeyObj* k) { return k && (k->pub || k->prov->key); }

DWORD KeyBits(KeyObj* k) {
    if (!k->pub) return k->prov->key->Bits();
    DWORD bits = 0, cb = 0;
    BCryptGetProperty(k->pub, BCRYPT_KEY_LENGTH, (PUCHAR)&bits, sizeof(bits), &cb, 0);
    return bits;
}

// PUBLICKEYBLOB z CAPI (BLOBHEADER, RSAPUBKEY, moduł little-endian) — w CNG to LEGACY_RSAPUBLIC_BLOB
bool PublicBlob(KeyObj* k, std::vector<BYTE>& blob) {
    DWORD cb = 0;
    if (k->pub) {
        if (!BCRYPT_SUCCESS(BCryptExportKey(k->pub, NULL, LEGACY_RSAPUBLIC_BLOB, NULL, 0, &cb, 0))) return false;
        blob.resize(cb);
        if (!BCRYPT_SUCCESS(BCryptExportKey(k->pub, NULL, LEGACY_RSAPUBLIC_BLOB, blob.data(), cb, &cb, 0))) return false;
    } else {
        sb::IKey* key = k->prov->key;
        if (key->ExportPublic(LEGACY_RSAPUBLIC_BLOB, NULL, 0, &cb) != ERROR_SUCCESS) return false;
        blob.resize(cb);
        if (key->ExportPublic(LEGACY_RSAPUBLIC_BLOB, blob.data(), cb, &cb) != ERROR_SUCCESS) return false;
    }
    if (cb < sizeof(BLOBHEADER) + sizeof(RSAPUBKEY)) return false;
    blob.resize(cb);
    ((BLOBHEADER*)blob.data())->aiKeyAlg = k->keySpec == AT_KEYEXCHANGE ? CALG_RSA_KEYX : CALG_RSA_SIGN;
    return true;
}

// Klucz publiczny z PUBLICKEYBLOB jako uchwyt BCrypt (NULL = zły blob). Przepisujemy go na format CNG:
// CAPI trzyma wykładnik jako liczbę, a moduł little-endian; BCRYPT_RSAPUBLIC_BLOB — oba big-endian.
BCRYPT_KEY_HANDLE ImportPublic(const BYTE* pbData, DWORD cbData) {
    const DWORD kHead = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY);
    BCRYPT_ALG_HANDLE rsa = RsaAlgHandle();
    if (!rsa || cbData < kHead) return NULL;
    const RSAPUBKEY* rp = (const RSAPUBKEY*)(pbData + sizeof(BLOBHEADER));
    DWORD cbMod = rp->bitlen / 8;
    if (rp->magic != 0x31415352 /* "RSA1" */ || !cbMod || (rp->bitlen % 8) || cbMod > 2048 || cbData - kHead < cbMod) return NULL;
    BYTE exp[4]; DWORD cbExp = 0;
    for (int i = 3; i >= 0; --i) { BYTE b = (BYTE)(rp->pubexp >> (8 * i)); if (cbExp || b) exp[cbExp++] = b; }
    if (!cbExp) return NULL;
    std::vector<BYTE> blob(sizeof(BCRYPT_RSAKEY_BLOB) + cbExp + cbMod);
    BCRYPT_RSAKEY_BLOB* hdr = (BCRYPT_RSAKEY_BLOB*)blob.data();
    hdr->Magic = BCRYPT_RSAPUBLIC_MAGIC; hdr->BitLength = rp->bitlen; hdr->cbPublicExp = cbExp; hdr->cbModulus = cbMod;
    memcpy(blob.data() + sizeof(*hdr), exp, cbExp);
    std::reverse_copy(pbData + kHead, pbData + kHead + cbMod, blob.data() + sizeof(*hdr) + cbExp);
    BCRYPT_KEY_HANDLE h = NULL;
    return BCRYPT_SUCCESS(BCryptImportKeyPair(rsa, NULL, BCRYPT_RSAPUBLIC_BLOB, &h, blob.data(), (ULONG)blob.size(), 0)) ? h : NULL;
}

bool Finish(HashObj* h) {
    if (h->done) return true;
    h->value.assign(h->alg->bytes, 0);
    if (!BCRYPT_SUCCESS(BCryptFinishHash(h->h, h->value.data(), (ULONG)h->value.size(), 0))) return false;
    h->done = true;
    return true;
}

// Algorytmy wyliczane przez PP_ENUMALGS: skróty z hashalg.h i podpis RSA
struct AlgRow { ALG_ID alg; DWORD bits, minBits, maxBits; const char* name; const char* longName; };
bool AlgRowAt(size_t i, AlgRow& r) {
    if (i < (size_t)sb::hashalg::kCount) {
        const Info& a = sb::hashalg::kAll[i];
        r = { a.algId, a.bytes * 8, a.bytes * 8, a.bytes * 8, a.name, a.longName };
        return true;
    }
    if (i == (size_t)sb::hashalg::kCount) { r = { CALG_RSA_SIGN, 2048, 1024, 16384, "RSA_SIGN", "RSA Signature" }; return true; }
    return false;
}

}  // namespace

namespace sb { namespace csp {
void SetBackendForTests(IBackend* backend) { g_testBackend = backend; }
}}  // namespace sb::csp

// ---------------------------------------------------------------------------
// Kontekst dostawcy
// ---------------------------------------------------------------------------

extern "C" BOOL WINAPI CPAcquireContext(HCRYPTPROV* phProv, LPCSTR szContainer, DWORD dwFlags, PVTableProvStruc pVTable) {
    sb::IBackend* backend = Backend();
    std::wstring name = ContainerName(szContainer);
    if (!phProv) return Fail(ERROR_INVALID_PARAMETER);
    *phProv = 0;
    if (dwFlags & (CRYPT_NEWKEYSET | CRYPT_DELETEKEYSET)) {
        SB_WARN(L"AcquireContext(kontener='%s', flags=0x%X): tworzenie i usuwanie kontenerów nieobsługiwane", name.c_str(), dwFlags);
        return Fail(NTE_BAD_FLAGS);
    }
    if (name.empty() && !(dwFlags & CRYPT_VERIFYCONTEXT)) {
        // kontener domyślny: pierwszy certyfikat RSA pobrany z komputera użytkownika
        std::vector<std::wstring> names = RsaContainers();
        if (names.empty()) { SB_WARN(L"AcquireContext(kontener domyślny): brak certyfikatów z komputera użytkownika"); return Fail(NTE_BAD_KEYSET); }
        name = names[0];
    }
    sb::IKey* key = nullptr;
    if (!name.empty()) {
        SECURITY_STATUS s = backend->Open(name, &key);
        if (s != ERROR_SUCCESS || !key) {
            SB_WARN(L"AcquireContext(kontener='%s', flags=0x%X): %s", name.c_str(), dwFlags, sb::StatusText(s).c_str());
            return Fail(s != ERROR_SUCCESS ? (DWORD)s : (DWORD)NTE_BAD_KEYSET);
        }
        if (!IsRsa(key)) {
            // CAPI nie zna ECDSA — taki certyfikat działa tylko przez dostawcę CNG
            SB_WARN(L"AcquireContext(kontener='%s'): klucz %s — CSP obsługuje tylko RSA", name.c_str(), key->AlgId());
            delete key;
            return Fail(NTE_BAD_ALGID);
        }
    }
    ProvObj* p = new (std::nothrow) ProvObj{ kProvMagic, {}, name, key, {}, 0, 0 };
    if (!p) { delete key; return Fail(NTE_NO_MEMORY); }
    p->provName = (pVTable && pVTable->Version >= 3 && pVTable->pszProvName && *pVTable->pszProvName)
                      ? std::string(pVTable->pszProvName) : ToAnsi(sb::keyprov::kCspName);
    if (key) SB_INFO(L"AcquireContext(kontener='%s', flags=0x%X): OK, RSA %lu bit", name.c_str(), dwFlags, key->Bits());
    else SB_TRACE(L"AcquireContext(bez kontenera, flags=0x%X): OK", dwFlags);
    *phProv = (HCRYPTPROV)p;
    return TRUE;
}

extern "C" BOOL WINAPI CPReleaseContext(HCRYPTPROV hProv, DWORD dwFlags) {
    ProvObj* p = AsProv(hProv);
    SB_TRACE(L"ReleaseContext()");
    if (!p) return Fail(NTE_BAD_UID);
    p->magic = 0;
    delete p->key;
    delete p;
    return TRUE;
}

extern "C" BOOL WINAPI CPGetProvParam(HCRYPTPROV hProv, DWORD dwParam, LPBYTE pbData, LPDWORD pcbDataLen, DWORD dwFlags) {
    ProvObj* p = AsProv(hProv);
    SB_TRACE(L"GetProvParam(param=%lu, flags=0x%X)", dwParam, dwFlags);
    if (!p) return Fail(NTE_BAD_UID);
    if (!pcbDataLen) return Fail(ERROR_INVALID_PARAMETER);
    switch (dwParam) {
    case PP_NAME: return OutAnsi(pbData, pcbDataLen, p->provName);
    case PP_CONTAINER:
    case PP_UNIQUE_CONTAINER: return OutAnsi(pbData, pcbDataLen, ToAnsi(p->container));
    case PP_PROVTYPE: return OutDword(pbData, pcbDataLen, sb::keyprov::kCspProvType);
    case PP_IMPTYPE: return OutDword(pbData, pcbDataLen, CRYPT_IMPL_HARDWARE | CRYPT_IMPL_REMOVABLE);
    case PP_VERSION: return OutDword(pbData, pcbDataLen, kCspVersion);
    case PP_KEYSPEC: return OutDword(pbData, pcbDataLen, AT_SIGNATURE | AT_KEYEXCHANGE);
    case PP_KEYSET_TYPE: return OutDword(pbData, pcbDataLen, 0);   // kontenery użytkownika, nie komputera
    case PP_ENUMCONTAINERS: {
        if (dwFlags & CRYPT_FIRST) { p->enumNames = RsaContainers(); p->enumName = 0; }
        if (p->enumName >= p->enumNames.size()) return Fail(ERROR_NO_MORE_ITEMS);
        if (!OutAnsi(pbData, pcbDataLen, ToAnsi(p->enumNames[p->enumName]))) return FALSE;
        if (pbData) ++p->enumName;   // samo pytanie o rozmiar nie przesuwa wyliczania
        return TRUE;
    }
    case PP_ENUMALGS:
    case PP_ENUMALGS_EX: {
        if (dwFlags & CRYPT_FIRST) p->enumAlg = 0;
        AlgRow r;
        if (!AlgRowAt(p->enumAlg, r)) return Fail(ERROR_NO_MORE_ITEMS);
        BOOL ok;
        if (dwParam == PP_ENUMALGS) {
            PROV_ENUMALGS e = {};
            e.aiAlgid = r.alg; e.dwBitLen = r.bits;
            strncpy_s(e.szName, r.name, _TRUNCATE); e.dwNameLen = (DWORD)strlen(e.szName) + 1;
            ok = Out(pbData, pcbDataLen, &e, sizeof(e));
        } else {
            PROV_ENUMALGS_EX e = {};
            e.aiAlgid = r.alg; e.dwDefaultLen = r.bits; e.dwMinLen = r.minBits; e.dwMaxLen = r.maxBits;
            strncpy_s(e.szName, r.name, _TRUNCATE); e.dwNameLen = (DWORD)strlen(e.szName) + 1;
            strncpy_s(e.szLongName, r.longName, _TRUNCATE); e.dwLongNameLen = (DWORD)strlen(e.szLongName) + 1;
            ok = Out(pbData, pcbDataLen, &e, sizeof(e));
        }
        if (ok && pbData) ++p->enumAlg;
        return ok;
    }
    }
    SB_TRACE(L"GetProvParam: nieobsługiwany parametr %lu", dwParam);
    return Fail(NTE_BAD_TYPE);
}

extern "C" BOOL WINAPI CPSetProvParam(HCRYPTPROV hProv, DWORD dwParam, const BYTE* pbData, DWORD dwFlags) {
    SB_TRACE(L"SetProvParam(param=%lu, flags=0x%X)", dwParam, dwFlags);
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    switch (dwParam) {
    case PP_CLIENT_HWND: return TRUE;   // okno PIN pokazuje sterownik karty na komputerze użytkownika
    case PP_KEYEXCHANGE_PIN:
    case PP_SIGNATURE_PIN:
        // Program próbuje podać PIN „po cichu”. Nie przyjmujemy go i nie zapisujemy — PIN zawsze wpisuje użytkownik lokalnie.
        SB_WARN(L"SetProvParam: program przekazuje PIN — ignorujemy (PIN zawsze lokalnie)");
        return TRUE;
    }
    return Fail(NTE_BAD_TYPE);
}

extern "C" BOOL WINAPI CPGenRandom(HCRYPTPROV hProv, DWORD cbLen, LPBYTE pbBuffer) {
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    if (!pbBuffer && cbLen) return Fail(ERROR_INVALID_PARAMETER);
    if (cbLen && !BCRYPT_SUCCESS(BCryptGenRandom(NULL, pbBuffer, cbLen, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) return Fail(NTE_FAIL);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Klucze
// ---------------------------------------------------------------------------

extern "C" BOOL WINAPI CPGetUserKey(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY* phUserKey) {
    ProvObj* p = AsProv(hProv);
    SB_TRACE(L"GetUserKey(spec=%lu)", dwKeySpec);
    if (!p) return Fail(NTE_BAD_UID);
    if (!phUserKey) return Fail(ERROR_INVALID_PARAMETER);
    *phUserKey = 0;
    // Karta ma jeden klucz; oddajemy go pod oboma oznaczeniami, bo część programów prosi zawsze o AT_KEYEXCHANGE
    if (!p->key || !ValidKeySpec(dwKeySpec)) return Fail(NTE_NO_KEY);
    KeyObj* k = new (std::nothrow) KeyObj{ kKeyMagic, p, dwKeySpec, NULL };
    if (!k) return Fail(NTE_NO_MEMORY);
    *phUserKey = (HCRYPTKEY)k;
    return TRUE;
}

extern "C" BOOL WINAPI CPGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey) {
    SB_INFO(L"GenKey(alg=0x%X, flags=0x%X) -> odmowa (klucze są tylko na karcie użytkownika)", Algid, dwFlags);
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    return Fail(NTE_BAD_ALGID);
}

extern "C" BOOL WINAPI CPDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hHash, DWORD dwFlags, HCRYPTKEY* phKey) {
    SB_INFO(L"DeriveKey(alg=0x%X) -> odmowa", Algid);
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    return Fail(NTE_BAD_ALGID);
}

extern "C" BOOL WINAPI CPDuplicateKey(HCRYPTPROV hProv, HCRYPTKEY hKey, LPDWORD pdwReserved, DWORD dwFlags, HCRYPTKEY* phKey) {
    KeyObj* k = AsKey(hKey);
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    if (!k) return Fail(NTE_BAD_KEY);
    if (!phKey) return Fail(ERROR_INVALID_PARAMETER);
    KeyObj* n = new (std::nothrow) KeyObj{ kKeyMagic, k->prov, k->keySpec, NULL };
    if (!n) return Fail(NTE_NO_MEMORY);
    if (k->pub) {
        // kopia zaimportowanego klucza publicznego: przez jego blob
        std::vector<BYTE> blob;
        if (PublicBlob(k, blob)) n->pub = ImportPublic(blob.data(), (DWORD)blob.size());
        if (!n->pub) { delete n; return Fail(NTE_FAIL); }
    }
    *phKey = (HCRYPTKEY)n;
    return TRUE;
}

extern "C" BOOL WINAPI CPDestroyKey(HCRYPTPROV hProv, HCRYPTKEY hKey) {
    KeyObj* k = (KeyObj*)hKey;
    if (!k || k->magic != kKeyMagic) return Fail(NTE_BAD_KEY);
    k->magic = 0;
    if (k->pub) BCryptDestroyKey(k->pub);
    delete k;
    return TRUE;
}

extern "C" BOOL WINAPI CPGetKeyParam(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, LPBYTE pbData, LPDWORD pcbDataLen, DWORD dwFlags) {
    KeyObj* k = AsKey(hKey);
    SB_TRACE(L"GetKeyParam(param=%lu)", dwParam);
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    if (!Usable(k)) return Fail(NTE_BAD_KEY);
    if (!pcbDataLen) return Fail(ERROR_INVALID_PARAMETER);
    switch (dwParam) {
    case KP_ALGID: return OutDword(pbData, pcbDataLen, k->keySpec == AT_KEYEXCHANGE ? CALG_RSA_KEYX : CALG_RSA_SIGN);
    case KP_KEYLEN:
    case KP_BLOCKLEN: return OutDword(pbData, pcbDataLen, KeyBits(k));
    case KP_PERMISSIONS: return OutDword(pbData, pcbDataLen, CRYPT_READ);   // bez CRYPT_EXPORT: klucz nie opuszcza karty
    case KP_CERTIFICATE: {
        if (k->pub) return Fail(NTE_BAD_TYPE);   // certyfikat ma tylko klucz z karty
        HCERTSTORE store = sb::certs::OpenMyStore();
        PCCERT_CONTEXT cert = store ? sb::certs::FindByThumbprint(store, k->prov->container) : NULL;
        BOOL ok = cert ? Out(pbData, pcbDataLen, cert->pbCertEncoded, cert->cbCertEncoded) : FALSE;
        DWORD e = cert ? GetLastError() : (DWORD)NTE_NOT_FOUND;
        if (cert) CertFreeCertificateContext(cert);
        if (store) CertCloseStore(store, 0);
        return ok ? TRUE : Fail(e);
    }
    }
    return Fail(NTE_BAD_TYPE);
}

extern "C" BOOL WINAPI CPSetKeyParam(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, const BYTE* pbData, DWORD dwFlags) {
    SB_TRACE(L"SetKeyParam(param=%lu) -> odmowa", dwParam);
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    if (!AsKey(hKey)) return Fail(NTE_BAD_KEY);
    return Fail(NTE_BAD_TYPE);
}

extern "C" BOOL WINAPI CPExportKey(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTKEY hPubKey, DWORD dwBlobType, DWORD dwFlags,
                                   LPBYTE pbData, LPDWORD pcbDataLen) {
    KeyObj* k = AsKey(hKey);
    SB_TRACE(L"ExportKey(blob=%lu, flags=0x%X)", dwBlobType, dwFlags);
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    if (!Usable(k)) return Fail(NTE_BAD_KEY);
    if (dwBlobType != PUBLICKEYBLOB) {
        SB_WARN(L"ExportKey: odmowa eksportu typu %lu (klucz prywatny nie opuszcza nośnika)", dwBlobType);
        return Fail(dwBlobType == PRIVATEKEYBLOB ? (DWORD)NTE_BAD_KEY_STATE : (DWORD)NTE_BAD_TYPE);
    }
    std::vector<BYTE> blob;
    if (!PublicBlob(k, blob)) return Fail(NTE_BAD_KEY);
    return Out(pbData, pcbDataLen, blob.data(), (DWORD)blob.size());
}

// Import wyłącznie klucza publicznego RSA (PUBLICKEYBLOB): program sprawdza nim podpis w tym samym kontekście
// (tak robi m.in. certutil). Kluczy prywatnych i sesyjnych nie przyjmujemy.
extern "C" BOOL WINAPI CPImportKey(HCRYPTPROV hProv, const BYTE* pbData, DWORD cbDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey) {
    ProvObj* p = AsProv(hProv);
    if (!p) return Fail(NTE_BAD_UID);
    if (!phKey) return Fail(ERROR_INVALID_PARAMETER);
    *phKey = 0;
    const BLOBHEADER* hdr = (const BLOBHEADER*)pbData;
    if (!pbData || cbDataLen < sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) || hdr->bType != PUBLICKEYBLOB ||
        (hdr->aiKeyAlg != CALG_RSA_SIGN && hdr->aiKeyAlg != CALG_RSA_KEYX)) {
        SB_INFO(L"ImportKey(cb=%lu, flags=0x%X) -> odmowa (przyjmujemy tylko klucz publiczny RSA)", cbDataLen, dwFlags);
        return Fail((DWORD)E_NOTIMPL);
    }
    KeyObj* k = new (std::nothrow) KeyObj{ kKeyMagic, p, hdr->aiKeyAlg == CALG_RSA_KEYX ? (DWORD)AT_KEYEXCHANGE : (DWORD)AT_SIGNATURE, NULL };
    if (!k) return Fail(NTE_NO_MEMORY);
    k->pub = ImportPublic(pbData, cbDataLen);
    if (!k->pub) { delete k; return Fail(NTE_BAD_DATA); }
    SB_TRACE(L"ImportKey(klucz publiczny RSA, %lu bit)", KeyBits(k));
    *phKey = (HCRYPTKEY)k;
    return TRUE;
}

extern "C" BOOL WINAPI CPEncrypt(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL fFinal, DWORD dwFlags,
                                 LPBYTE pbData, LPDWORD pcbDataLen, DWORD cbBufLen) {
    SB_INFO(L"Encrypt -> odmowa");
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    return Fail((DWORD)E_NOTIMPL);
}

extern "C" BOOL WINAPI CPDecrypt(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL fFinal, DWORD dwFlags,
                                 LPBYTE pbData, LPDWORD pcbDataLen) {
    SB_INFO(L"Decrypt -> odmowa");
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    return Fail((DWORD)E_NOTIMPL);
}

// ---------------------------------------------------------------------------
// Skróty
// ---------------------------------------------------------------------------

extern "C" BOOL WINAPI CPCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash) {
    SB_TRACE(L"CreateHash(alg=0x%X, flags=0x%X)", Algid, dwFlags);
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    if (!phHash) return Fail(ERROR_INVALID_PARAMETER);
    *phHash = 0;
    const Info* a = sb::hashalg::ByAlgId(Algid);
    if (!a) { SB_WARN(L"CreateHash: nieobsługiwany algorytm 0x%X", Algid); return Fail(NTE_BAD_ALGID); }
    if (hKey) return Fail(NTE_BAD_KEY);   // skróty z kluczem (HMAC, MAC) — nieobsługiwane
    if (dwFlags) return Fail(NTE_BAD_FLAGS);
    BCRYPT_ALG_HANDLE ha = AlgHandle(a);
    if (!ha) return Fail(NTE_FAIL);
    HashObj* h = new (std::nothrow) HashObj{ kHashMagic, a, NULL, false, {} };
    if (!h) return Fail(NTE_NO_MEMORY);
    if (!BCRYPT_SUCCESS(BCryptCreateHash(ha, &h->h, NULL, 0, NULL, 0, 0))) { delete h; return Fail(NTE_FAIL); }
    *phHash = (HCRYPTHASH)h;
    return TRUE;
}

extern "C" BOOL WINAPI CPDuplicateHash(HCRYPTPROV hProv, HCRYPTHASH hHash, LPDWORD pdwReserved, DWORD dwFlags, HCRYPTHASH* phHash) {
    HashObj* h = AsHash(hHash);
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    if (!h) return Fail(NTE_BAD_HASH);
    if (!phHash) return Fail(ERROR_INVALID_PARAMETER);
    HashObj* n = new (std::nothrow) HashObj{ kHashMagic, h->alg, NULL, h->done, h->value };
    if (!n) return Fail(NTE_NO_MEMORY);
    if (!h->done && !BCRYPT_SUCCESS(BCryptDuplicateHash(h->h, &n->h, NULL, 0, 0))) { delete n; return Fail(NTE_FAIL); }
    *phHash = (HCRYPTHASH)n;
    return TRUE;
}

extern "C" BOOL WINAPI CPHashData(HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE* pbData, DWORD cbDataLen, DWORD dwFlags) {
    HashObj* h = AsHash(hHash);
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    if (!h) return Fail(NTE_BAD_HASH);
    if (dwFlags) return Fail(NTE_BAD_FLAGS);
    if (h->done) return Fail(NTE_BAD_HASH_STATE);
    if (!pbData && cbDataLen) return Fail(ERROR_INVALID_PARAMETER);
    if (cbDataLen && !BCRYPT_SUCCESS(BCryptHashData(h->h, (PUCHAR)pbData, cbDataLen, 0))) return Fail(NTE_FAIL);
    return TRUE;
}

extern "C" BOOL WINAPI CPHashSessionKey(HCRYPTPROV hProv, HCRYPTHASH hHash, HCRYPTKEY hKey, DWORD dwFlags) {
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    return Fail((DWORD)E_NOTIMPL);
}

extern "C" BOOL WINAPI CPSetHashParam(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, const BYTE* pbData, DWORD dwFlags) {
    HashObj* h = AsHash(hHash);
    SB_TRACE(L"SetHashParam(param=%lu)", dwParam);
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    if (!h) return Fail(NTE_BAD_HASH);
    if (dwParam != HP_HASHVAL) return Fail(NTE_BAD_TYPE);
    if (!pbData) return Fail(ERROR_INVALID_PARAMETER);
    // CAPI nie podaje tu długości: gotowy skrót ma zawsze długość właściwą dla algorytmu, z którym utworzono obiekt
    h->value.assign(pbData, pbData + h->alg->bytes);
    h->done = true;
    return TRUE;
}

extern "C" BOOL WINAPI CPGetHashParam(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, LPBYTE pbData, LPDWORD pcbDataLen, DWORD dwFlags) {
    HashObj* h = AsHash(hHash);
    SB_TRACE(L"GetHashParam(param=%lu)", dwParam);
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    if (!h) return Fail(NTE_BAD_HASH);
    if (!pcbDataLen) return Fail(ERROR_INVALID_PARAMETER);
    switch (dwParam) {
    case HP_ALGID: return OutDword(pbData, pcbDataLen, h->alg->algId);
    case HP_HASHSIZE: return OutDword(pbData, pcbDataLen, h->alg->bytes);
    case HP_HASHVAL:
        if (!pbData) { *pcbDataLen = h->alg->bytes; return TRUE; }
        if (*pcbDataLen < h->alg->bytes) { *pcbDataLen = h->alg->bytes; return Fail(ERROR_MORE_DATA); }
        if (!Finish(h)) return Fail(NTE_BAD_HASH_STATE);
        return Out(pbData, pcbDataLen, h->value.data(), (DWORD)h->value.size());
    }
    return Fail(NTE_BAD_TYPE);
}

extern "C" BOOL WINAPI CPDestroyHash(HCRYPTPROV hProv, HCRYPTHASH hHash) {
    HashObj* h = AsHash(hHash);
    if (!h) return Fail(NTE_BAD_HASH);
    h->magic = 0;
    if (h->h) BCryptDestroyHash(h->h);
    delete h;
    return TRUE;
}

// ---------------------------------------------------------------------------
// Podpis
// ---------------------------------------------------------------------------

extern "C" BOOL WINAPI CPSignHash(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwKeySpec, LPCWSTR szDescription, DWORD dwFlags,
                                  LPBYTE pbSignature, LPDWORD pcbSigLen) {
    ProvObj* p = AsProv(hProv);
    HashObj* h = AsHash(hHash);
    if (!p) return Fail(NTE_BAD_UID);
    if (!h) return Fail(NTE_BAD_HASH);
    if (!pcbSigLen) return Fail(ERROR_INVALID_PARAMETER);
    if (!p->key || !ValidKeySpec(dwKeySpec)) return Fail(NTE_NO_KEY);
    if (dwFlags) {
        // CRYPT_NOHASHOID / CRYPT_X931_FORMAT: podpis bez identyfikatora skrótu — nie do dokumentów, odmawiamy
        SB_WARN(L"SignHash: nieobsługiwane flagi 0x%X", dwFlags);
        return Fail(NTE_BAD_FLAGS);
    }
    DWORD cbSig = (p->key->Bits() + 7) / 8;
    if (!pbSignature) {
        // pytanie o rozmiar podpisu: bez kanału i bez PIN-u
        *pcbSigLen = cbSig;
        return TRUE;
    }
    if (*pcbSigLen < cbSig) { *pcbSigLen = cbSig; return Fail(ERROR_MORE_DATA); }
    if (!Finish(h)) return Fail(NTE_BAD_HASH_STATE);
    // długość skrótu musi odpowiadać algorytmowi, zanim cokolwiek pójdzie kanałem do karty
    if (h->value.size() != h->alg->bytes) return Fail(NTE_BAD_HASH);

    BCRYPT_PKCS1_PADDING_INFO pad = { h->alg->cngName };
    std::vector<BYTE> sig(cbSig);
    DWORD cb = 0;
    SB_INFO(L">>> SignHash: klucz='%s', PKCS1(hash=%s), skrót %lu B [%s], bufor %lu B",
            p->container.c_str(), h->alg->cngName, (DWORD)h->value.size(), Hex(h->value.data(), h->value.size(), 8).c_str(), *pcbSigLen);
    ULONGLONG t0 = GetTickCount64();
    SECURITY_STATUS s = p->key->SignHash(&pad, h->value.data(), (DWORD)h->value.size(), sig.data(), cbSig, &cb, NCRYPT_PAD_PKCS1_FLAG);
    SB_INFO(L"<<< SignHash: %s, %lu B, %llu ms", sb::StatusText(s).c_str(), cb, GetTickCount64() - t0);
    if (s != ERROR_SUCCESS) return Fail((DWORD)s);
    if (cb != cbSig) {
        SB_ERROR(L"SignHash: podpis ma %lu B, a klucz %lu B — odrzucony", cb, cbSig);
        return Fail(NTE_BAD_SIGNATURE);
    }
    // karta i CNG oddają podpis big-endian, CAPI oczekuje little-endian
    std::reverse_copy(sig.begin(), sig.end(), pbSignature);
    *pcbSigLen = cbSig;
    return TRUE;
}

// Weryfikacja kluczem publicznym — naszego certyfikatu albo zaimportowanym przez program (lokalnie, bez kanału)
extern "C" BOOL WINAPI CPVerifySignature(HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE* pbSignature, DWORD cbSigLen, HCRYPTKEY hPubKey,
                                         LPCWSTR szDescription, DWORD dwFlags) {
    HashObj* h = AsHash(hHash);
    KeyObj* k = AsKey(hPubKey);
    SB_TRACE(L"VerifySignature(sig %lu B, flags=0x%X)", cbSigLen, dwFlags);
    if (!AsProv(hProv)) return Fail(NTE_BAD_UID);
    if (!h) return Fail(NTE_BAD_HASH);
    if (!Usable(k)) return Fail(NTE_BAD_KEY);
    if (dwFlags) return Fail(NTE_BAD_FLAGS);
    if (!pbSignature || !cbSigLen) return Fail(NTE_BAD_SIGNATURE);
    if (!Finish(h)) return Fail(NTE_BAD_HASH_STATE);
    std::vector<BYTE> be(cbSigLen);
    std::reverse_copy(pbSignature, pbSignature + cbSigLen, be.begin());
    BCRYPT_PKCS1_PADDING_INFO pad = { h->alg->cngName };
    bool ok = k->pub ? BCRYPT_SUCCESS(BCryptVerifySignature(k->pub, &pad, h->value.data(), (ULONG)h->value.size(), be.data(), cbSigLen, BCRYPT_PAD_PKCS1))
                     : k->prov->key->VerifySignature(&pad, h->value.data(), (DWORD)h->value.size(), be.data(), cbSigLen, NCRYPT_PAD_PKCS1_FLAG) == ERROR_SUCCESS;
    return ok ? TRUE : Fail(NTE_BAD_SIGNATURE);
}

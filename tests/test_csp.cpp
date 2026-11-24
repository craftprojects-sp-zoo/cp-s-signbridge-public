// SignBridge — © 2026 Craftprojects Sp. z o.o. (craftprojects.pl)
// Dostawca CAPI (CSP): kolejność bajtów podpisu (CAPI little-endian, CNG big-endian), skróty SHA-256/384/512 i SHA-1,
// odmowa dla ECDSA i nieobsługiwanych algorytmów, długość skrótu na wejściu, ładowanie biblioteki przez CryptoAPI.
// Zamiast kanału RDP i karty: backend testowy z kluczem RSA w pamięci (podpisuje jak karta — PKCS#1, big-endian).
#include "check.h"
#include "testcert.h"
#include "csp.h"
#include "backend.h"
#include "log.h"
#include "hashalg.h"
#include "keyprov.h"
#include "kspsetup.h"
#include "certs.h"
#include <algorithm>
#include <string.h>

namespace {

const char* const kRsaName = "00112233445566778899AABBCCDDEEFF00112233";
const char* const kEcName = "FFEEDDCCBBAA99887766554433221100FFEEDDCC";
const wchar_t* const kRsaNameW = L"00112233445566778899AABBCCDDEEFF00112233";
const wchar_t* const kEcNameW = L"FFEEDDCCBBAA99887766554433221100FFEEDDCC";

// Co dostawca wysłał „do karty” i jak karta ma odpowiedzieć
struct Card {
    int calls = 0;
    std::wstring hashAlg;
    std::vector<BYTE> hash;
    DWORD flags = 0;
    SECURITY_STATUS fail = ERROR_SUCCESS;   // np. anulowany PIN
    bool shortSignature = false;            // zepsuta odpowiedź z kanału
} g_card;

BCRYPT_KEY_HANDLE GenerateKey(LPCWSTR alg, ULONG bits) {
    BCRYPT_ALG_HANDLE ha = NULL; BCRYPT_KEY_HANDLE hk = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&ha, alg, NULL, 0))) return NULL;
    if (BCRYPT_SUCCESS(BCryptGenerateKeyPair(ha, &hk, bits, 0)) && !BCRYPT_SUCCESS(BCryptFinalizeKeyPair(hk, 0))) { BCryptDestroyKey(hk); hk = NULL; }
    return hk;   // uchwyt algorytmu żyje do końca procesu testów
}
BCRYPT_KEY_HANDLE RsaKey() { static BCRYPT_KEY_HANDLE k = GenerateKey(BCRYPT_RSA_ALGORITHM, 2048); return k; }
BCRYPT_KEY_HANDLE EcKey() { static BCRYPT_KEY_HANDLE k = GenerateKey(BCRYPT_ECDSA_P256_ALGORITHM, 256); return k; }

class TestKey : public sb::IKey {
public:
    TestKey(const std::wstring& name, BCRYPT_KEY_HANDLE h, bool ec) : name_(name), h_(h), ec_(ec) {}
    const std::wstring& Name() const override { return name_; }
    const wchar_t* AlgGroup() const override { return ec_ ? NCRYPT_ECDSA_ALGORITHM_GROUP : NCRYPT_RSA_ALGORITHM_GROUP; }
    const wchar_t* AlgId() const override { return ec_ ? BCRYPT_ECDSA_P256_ALGORITHM : BCRYPT_RSA_ALGORITHM; }
    DWORD Bits() const override { return ec_ ? 256 : 2048; }
    bool IsFinalized() const override { return true; }
    SECURITY_STATUS ExportPublic(LPCWSTR blobType, PBYTE pbOut, DWORD cbOut, DWORD* pcb) override {
        NTSTATUS st = BCryptExportKey(h_, NULL, blobType, pbOut, cbOut, pcb, 0);
        if (st == STATUS_BUFFER_TOO_SMALL) return NTE_BUFFER_TOO_SMALL;
        return BCRYPT_SUCCESS(st) ? ERROR_SUCCESS : NTE_NOT_SUPPORTED;
    }
    SECURITY_STATUS SignHash(VOID* pPad, PBYTE pbHash, DWORD cbHash, PBYTE pbSig, DWORD cbSig, DWORD* pcb, DWORD dwFlags) override {
        auto* p = (BCRYPT_PKCS1_PADDING_INFO*)pPad;
        ++g_card.calls;
        g_card.hashAlg = (p && p->pszAlgId) ? p->pszAlgId : L"";
        g_card.hash.assign(pbHash, pbHash + cbHash);
        g_card.flags = dwFlags;
        if (g_card.fail != ERROR_SUCCESS) return g_card.fail;
        NTSTATUS st = BCryptSignHash(h_, pPad, pbHash, cbHash, pbSig, cbSig, pcb, BCRYPT_PAD_PKCS1);
        if (BCRYPT_SUCCESS(st) && g_card.shortSignature) --*pcb;
        return BCRYPT_SUCCESS(st) ? ERROR_SUCCESS : NTE_FAIL;
    }
    SECURITY_STATUS VerifySignature(VOID* pPad, PBYTE pbHash, DWORD cbHash, PBYTE pbSig, DWORD cbSig, DWORD) override {
        return BCRYPT_SUCCESS(BCryptVerifySignature(h_, pPad, pbHash, cbHash, pbSig, cbSig, BCRYPT_PAD_PKCS1)) ? ERROR_SUCCESS : NTE_BAD_SIGNATURE;
    }
    SECURITY_STATUS Decrypt(VOID*, PBYTE, DWORD, PBYTE, DWORD, DWORD*, DWORD) override { return NTE_NOT_SUPPORTED; }
    SECURITY_STATUS SetProperty(LPCWSTR, PBYTE, DWORD, DWORD) override { return ERROR_SUCCESS; }
    SECURITY_STATUS Finalize(DWORD) override { return NTE_NOT_SUPPORTED; }
private:
    std::wstring name_; BCRYPT_KEY_HANDLE h_; bool ec_;
};

class TestBackend : public sb::IBackend {
public:
    const wchar_t* Name() const override { return L"test"; }
    DWORD ImplType() const override { return NCRYPT_IMPL_HARDWARE_FLAG; }
    SECURITY_STATUS Open(const std::wstring& name, sb::IKey** ppKey) override {
        if (name == kRsaNameW && RsaKey()) { *ppKey = new TestKey(name, RsaKey(), false); return ERROR_SUCCESS; }
        if (name == kEcNameW && EcKey()) { *ppKey = new TestKey(name, EcKey(), true); return ERROR_SUCCESS; }
        return NTE_BAD_KEYSET;
    }
    SECURITY_STATUS Create(const std::wstring&, LPCWSTR, sb::IKey**) override { return NTE_NOT_SUPPORTED; }
    SECURITY_STATUS Delete(const std::wstring&) override { return NTE_NOT_SUPPORTED; }
    SECURITY_STATUS Enumerate(std::vector<std::wstring>& names) override { names.push_back(kEcNameW); names.push_back(kRsaNameW); return ERROR_SUCCESS; }
};

// Kontekst dostawcy na backendzie testowym. Log tylko do katalogu tymczasowego: test logu (test_ksp.cpp) stoi
// w CMakeLists przed tym plikiem i zwykle ustawia go pierwszy; gdyby kolejność się zmieniła, ustawiamy go tutaj.
struct Ctx {
    HCRYPTPROV h = 0; BOOL ok = FALSE; DWORD err = 0;
    Ctx(const char* container, DWORD flags = 0) {
        static TestBackend backend;
        if (sb::LogPath().empty()) sb::LogInitAt(t::TempDir(L"csp-logs"), L"t");
        sb::csp::SetBackendForTests(&backend);
        g_card.fail = ERROR_SUCCESS; g_card.shortSignature = false;
        ok = CPAcquireContext(&h, container, flags, NULL);
        err = GetLastError();
    }
    ~Ctx() { if (h) CPReleaseContext(h, 0); }
};

std::vector<BYTE> Digest(LPCWSTR alg, const BYTE* data, DWORD cb) {
    BCRYPT_ALG_HANDLE ha = NULL; DWORD len = 0, got = 0;
    std::vector<BYTE> out;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&ha, alg, NULL, 0))) return out;
    BCryptGetProperty(ha, BCRYPT_HASH_LENGTH, (PUCHAR)&len, sizeof(len), &got, 0);
    out.resize(len);
    if (!BCRYPT_SUCCESS(BCryptHash(ha, NULL, 0, (PUCHAR)data, cb, out.data(), len))) out.clear();
    BCryptCloseAlgorithmProvider(ha, 0);
    return out;
}

bool VerifyCng(LPCWSTR alg, const std::vector<BYTE>& digest, const std::vector<BYTE>& sig) {
    BCRYPT_PKCS1_PADDING_INFO pad = { alg };
    return BCRYPT_SUCCESS(BCryptVerifySignature(RsaKey(), &pad, (PUCHAR)digest.data(), (ULONG)digest.size(), (PUCHAR)sig.data(), (ULONG)sig.size(), BCRYPT_PAD_PKCS1));
}

HCRYPTHASH HashOf(HCRYPTPROV prov, ALG_ID alg, const BYTE* data, DWORD cb) {
    HCRYPTHASH hh = 0;
    if (!CPCreateHash(prov, alg, 0, 0, &hh)) return 0;
    if (!CPHashData(prov, hh, data, cb, 0)) { CPDestroyHash(prov, hh); return 0; }
    return hh;
}

const BYTE kMsg[] = "SignBridge: dokument do podpisu";
// SHA-256("abc"), FIPS 180-2
const BYTE kSha256Abc[32] = { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                              0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad };

std::wstring ExeDir() {
    wchar_t p[MAX_PATH]; GetModuleFileNameW(NULL, p, MAX_PATH);
    std::wstring s(p);
    return s.substr(0, s.find_last_of(L"\\/"));
}

}  // namespace

// Podpis przez CAPI ma odwrotną kolejność bajtów niż podpis z karty i CNG — dla każdego obsługiwanego skrótu
TEST(csp_sign_capi_byte_order_all_hashes) {
    Ctx c(kRsaName);
    CHECK(c.ok);
    if (!c.ok) return;
    HCRYPTKEY hKey = 0;
    CHECK(CPGetUserKey(c.h, AT_SIGNATURE, &hKey));

    // klucz publiczny tak, jak go dostaje program (PUBLICKEYBLOB) — do dostawcy Microsoftu, który jest tu
    // niezależnym sędzią formatu klucza i kolejności bajtów podpisu
    DWORD cbPub = 0;
    CHECK(CPExportKey(c.h, hKey, 0, PUBLICKEYBLOB, 0, NULL, &cbPub));
    std::vector<BYTE> pub(cbPub);
    CHECK(CPExportKey(c.h, hKey, 0, PUBLICKEYBLOB, 0, pub.data(), &cbPub));
    HCRYPTPROV ms = 0; HCRYPTKEY msPub = 0;
    CHECK(CryptAcquireContextW(&ms, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
    CHECK(CryptImportKey(ms, pub.data(), cbPub, 0, 0, &msPub));
    // ten sam klucz publiczny zaimportowany do naszego dostawcy (program sprawdza podpis w tym samym kontekście)
    HCRYPTKEY imported = 0; DWORD bits = 0, cbBits = sizeof(bits);
    CHECK(CPImportKey(c.h, pub.data(), cbPub, 0, 0, &imported));
    CHECK(CPGetKeyParam(c.h, imported, KP_KEYLEN, (LPBYTE)&bits, &cbBits, 0) && bits == 2048);
    std::vector<BYTE> pub2(cbPub); DWORD cbPub2 = cbPub;
    CHECK(CPExportKey(c.h, imported, 0, PUBLICKEYBLOB, 0, pub2.data(), &cbPub2) && cbPub2 == cbPub && pub2 == pub);

    for (const sb::hashalg::Info& a : sb::hashalg::kAll) {
        std::printf("    %s\n", a.name);
        std::vector<BYTE> digest = Digest(a.cngName, kMsg, sizeof(kMsg));
        CHECK(digest.size() == a.bytes);

        // (a) program liczy skrót u dostawcy: CryptCreateHash + CryptHashData + CryptSignHash
        HCRYPTHASH hh = HashOf(c.h, a.algId, kMsg, sizeof(kMsg));
        CHECK(hh != 0);
        int before = g_card.calls;
        DWORD cb = 0;
        CHECK(CPSignHash(c.h, hh, AT_SIGNATURE, NULL, 0, NULL, &cb) && cb == 256);
        CHECK(g_card.calls == before);   // pytanie o rozmiar nie idzie do karty (bez PIN-u)
        std::vector<BYTE> sig(cb);
        CHECK(CPSignHash(c.h, hh, AT_SIGNATURE, NULL, 0, sig.data(), &cb) && cb == 256);
        CHECK(g_card.calls == before + 1);
        // do karty poszedł właściwy skrót, o długości właściwej dla algorytmu, z nazwą algorytmu i dopełnieniem PKCS#1
        CHECK(g_card.hashAlg == a.cngName);
        CHECK(g_card.hash == digest && g_card.hash.size() == a.bytes);
        CHECK(g_card.flags == NCRYPT_PAD_PKCS1_FLAG);

        // kolejność bajtów: w CNG (big-endian) poprawny jest podpis odwrócony, a w postaci z CAPI — nie
        std::vector<BYTE> be(sig.rbegin(), sig.rend());
        CHECK(VerifyCng(a.cngName, digest, be));
        CHECK(!VerifyCng(a.cngName, digest, sig));
        // dostawca Microsoftu przyjmuje podpis dokładnie w postaci oddanej przez nasz CSP
        HCRYPTHASH mh = 0;
        CHECK(CryptCreateHash(ms, a.algId, 0, 0, &mh) && CryptHashData(mh, kMsg, sizeof(kMsg), 0));
        CHECK(CryptVerifySignatureW(mh, sig.data(), cb, msPub, NULL, 0));
        if (mh) CryptDestroyHash(mh);

        // (b) program podaje gotowy skrót (HP_HASHVAL) — tak robi .NET Framework; PKCS#1 v1.5 daje ten sam podpis
        HCRYPTHASH h2 = 0;
        CHECK(CPCreateHash(c.h, a.algId, 0, 0, &h2) && CPSetHashParam(c.h, h2, HP_HASHVAL, digest.data(), 0));
        std::vector<BYTE> sig2(256); DWORD cb2 = 256;
        CHECK(CPSignHash(c.h, h2, AT_SIGNATURE, NULL, 0, sig2.data(), &cb2) && cb2 == 256);
        CHECK(sig2 == sig);
        CHECK(g_card.hash == digest);

        // weryfikacja u naszego dostawcy (podpis w kolejności CAPI); zmieniony bajt = zły podpis
        HCRYPTHASH h3 = HashOf(c.h, a.algId, kMsg, sizeof(kMsg));
        CHECK(CPVerifySignature(c.h, h3, sig.data(), cb, hKey, NULL, 0));
        CHECK(CPVerifySignature(c.h, h3, sig.data(), cb, imported, NULL, 0));
        sig2[10] ^= 0x01;
        CHECK(!CPVerifySignature(c.h, h3, sig2.data(), cb2, hKey, NULL, 0) && GetLastError() == (DWORD)NTE_BAD_SIGNATURE);
        CHECK(!CPVerifySignature(c.h, h3, sig2.data(), cb2, imported, NULL, 0) && GetLastError() == (DWORD)NTE_BAD_SIGNATURE);
        CPDestroyHash(c.h, hh); CPDestroyHash(c.h, h2); CPDestroyHash(c.h, h3);
    }
    // ten sam klucz pod oznaczeniem AT_KEYEXCHANGE (programy, które zawsze o nie proszą)
    HCRYPTHASH hx = HashOf(c.h, CALG_SHA_256, kMsg, sizeof(kMsg));
    std::vector<BYTE> sx(256); DWORD cbx = 256;
    CHECK(CPSignHash(c.h, hx, AT_KEYEXCHANGE, NULL, 0, sx.data(), &cbx));
    CHECK(VerifyCng(BCRYPT_SHA256_ALGORITHM, Digest(BCRYPT_SHA256_ALGORITHM, kMsg, sizeof(kMsg)), std::vector<BYTE>(sx.rbegin(), sx.rend())));
    CPDestroyHash(c.h, hx);

    if (msPub) CryptDestroyKey(msPub);
    if (ms) CryptReleaseContext(ms, 0);
    CHECK(CPDestroyKey(c.h, imported));
    CHECK(CPDestroyKey(c.h, hKey));
}

// ECDSA i algorytmy spoza zakresu: odmowa po stronie serwera, nic nie trafia do kanału
TEST(csp_refuses_ecdsa_and_unsupported_algorithms) {
    Ctx ec(kEcName);
    CHECK(!ec.ok && ec.err == (DWORD)NTE_BAD_ALGID && ec.h == 0);

    Ctx c(kRsaName);
    CHECK(c.ok);
    if (!c.ok) return;
    int before = g_card.calls;

    // wyliczanie kontenerów pokazuje tylko klucze RSA
    char name[128] = {}; DWORD cb = sizeof(name);
    CHECK(CPGetProvParam(c.h, PP_ENUMCONTAINERS, (LPBYTE)name, &cb, CRYPT_FIRST) && strcmp(name, kRsaName) == 0);
    cb = sizeof(name);
    CHECK(!CPGetProvParam(c.h, PP_ENUMCONTAINERS, (LPBYTE)name, &cb, 0) && GetLastError() == ERROR_NO_MORE_ITEMS);

    for (ALG_ID alg : { (ALG_ID)CALG_MD5, (ALG_ID)CALG_MD2, (ALG_ID)CALG_SSL3_SHAMD5, (ALG_ID)CALG_HMAC, (ALG_ID)CALG_MAC,
                        (ALG_ID)CALG_ECDSA, (ALG_ID)CALG_RSA_SIGN, (ALG_ID)0 }) {
        HCRYPTHASH hh = 1;
        CHECK(!CPCreateHash(c.h, alg, 0, 0, &hh) && GetLastError() == (DWORD)NTE_BAD_ALGID && hh == 0);
    }
    HCRYPTKEY k = 0;
    CHECK(!CPGenKey(c.h, CALG_RSA_SIGN, 0, &k) && GetLastError() == (DWORD)NTE_BAD_ALGID);
    CHECK(!CPGenKey(c.h, CALG_ECDSA, 0, &k) && GetLastError() == (DWORD)NTE_BAD_ALGID);
    CHECK(!CPDeriveKey(c.h, CALG_AES_256, 0, 0, &k) && GetLastError() == (DWORD)NTE_BAD_ALGID);

    // podpis bez identyfikatora skrótu (CRYPT_NOHASHOID), X9.31 i nieznane oznaczenie klucza
    HCRYPTHASH hh = HashOf(c.h, CALG_SHA_256, kMsg, sizeof(kMsg));
    BYTE sig[256]; DWORD cbSig = sizeof(sig);
    CHECK(!CPSignHash(c.h, hh, AT_SIGNATURE, NULL, CRYPT_NOHASHOID, sig, &cbSig) && GetLastError() == (DWORD)NTE_BAD_FLAGS);
    CHECK(!CPSignHash(c.h, hh, AT_SIGNATURE, NULL, CRYPT_X931_FORMAT, sig, &cbSig) && GetLastError() == (DWORD)NTE_BAD_FLAGS);
    CHECK(!CPSignHash(c.h, hh, 3, NULL, 0, sig, &cbSig) && GetLastError() == (DWORD)NTE_NO_KEY);

    // klucz prywatny nie opuszcza karty; szyfrowania i importu nie ma
    CHECK(CPGetUserKey(c.h, AT_SIGNATURE, &k));
    BYTE blob[2048]; DWORD cbBlob = sizeof(blob);
    CHECK(!CPExportKey(c.h, k, 0, PRIVATEKEYBLOB, 0, blob, &cbBlob) && GetLastError() == (DWORD)NTE_BAD_KEY_STATE);
    cbBlob = sizeof(blob);
    CHECK(!CPExportKey(c.h, k, 0, SIMPLEBLOB, 0, blob, &cbBlob) && GetLastError() == (DWORD)NTE_BAD_TYPE);
    HCRYPTKEY imported = 0; cbBlob = 16;
    CHECK(!CPImportKey(c.h, blob, 16, 0, 0, &imported) && GetLastError() == (DWORD)E_NOTIMPL);
    // import przyjmuje tylko klucz publiczny RSA: blob oznaczony jako klucz prywatny — odmowa
    BYTE priv[sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + 256] = {};
    ((BLOBHEADER*)priv)->bType = PRIVATEKEYBLOB; ((BLOBHEADER*)priv)->bVersion = CUR_BLOB_VERSION; ((BLOBHEADER*)priv)->aiKeyAlg = CALG_RSA_SIGN;
    CHECK(!CPImportKey(c.h, priv, sizeof(priv), 0, 0, &imported) && GetLastError() == (DWORD)E_NOTIMPL && imported == 0);
    CHECK(!CPDecrypt(c.h, k, 0, TRUE, 0, blob, &cbBlob) && GetLastError() == (DWORD)E_NOTIMPL);
    CHECK(!CPEncrypt(c.h, k, 0, TRUE, 0, blob, &cbBlob, sizeof(blob)) && GetLastError() == (DWORD)E_NOTIMPL);
    CPDestroyKey(c.h, k);
    CPDestroyHash(c.h, hh);

    CHECK(g_card.calls == before);   // żadna z odmów nie dotarła do karty
}

// Kontekst, parametry dostawcy i klucza; błąd z karty wraca do programu bez zmian
TEST(csp_context_parameters_and_card_errors) {
    Ctx missing("0000000000000000000000000000000000000000");
    CHECK(!missing.ok && missing.err == (DWORD)NTE_BAD_KEYSET);
    Ctx created(kRsaName, CRYPT_NEWKEYSET);
    CHECK(!created.ok && created.err == (DWORD)NTE_BAD_FLAGS);
    Ctx deleted(kRsaName, CRYPT_DELETEKEYSET);
    CHECK(!deleted.ok && deleted.err == (DWORD)NTE_BAD_FLAGS);

    // kontekst bez klucza (CRYPT_VERIFYCONTEXT): skróty działają, klucza nie ma
    {
        Ctx v(NULL, CRYPT_VERIFYCONTEXT);
        CHECK(v.ok);
        HCRYPTKEY k = 0;
        CHECK(!CPGetUserKey(v.h, AT_SIGNATURE, &k) && GetLastError() == (DWORD)NTE_NO_KEY);
        HCRYPTHASH hh = HashOf(v.h, CALG_SHA_256, (const BYTE*)"abc", 3);
        BYTE sig[256]; DWORD cb = sizeof(sig);
        CHECK(!CPSignHash(v.h, hh, AT_SIGNATURE, NULL, 0, sig, &cb) && GetLastError() == (DWORD)NTE_NO_KEY);
        CPDestroyHash(v.h, hh);
    }
    // kontener domyślny (bez nazwy): pierwszy klucz RSA
    {
        Ctx d(NULL, 0);
        CHECK(d.ok);
        char name[128] = {}; DWORD cb = sizeof(name);
        CHECK(CPGetProvParam(d.h, PP_CONTAINER, (LPBYTE)name, &cb, 0) && strcmp(name, kRsaName) == 0);
    }

    Ctx c(kRsaName);
    CHECK(c.ok);
    if (!c.ok) return;
    char name[128] = {}; DWORD cb = 0, v = 0;
    CHECK(CPGetProvParam(c.h, PP_NAME, NULL, &cb, 0) && cb == strlen("SignBridge Cryptographic Provider") + 1);
    cb = 4;
    CHECK(!CPGetProvParam(c.h, PP_NAME, (LPBYTE)name, &cb, 0) && GetLastError() == ERROR_MORE_DATA && cb > 4);
    cb = sizeof(name);
    CHECK(CPGetProvParam(c.h, PP_NAME, (LPBYTE)name, &cb, 0) && strcmp(name, "SignBridge Cryptographic Provider") == 0);
    cb = sizeof(name);
    CHECK(CPGetProvParam(c.h, PP_CONTAINER, (LPBYTE)name, &cb, 0) && strcmp(name, kRsaName) == 0);
    cb = sizeof(v);
    CHECK(CPGetProvParam(c.h, PP_PROVTYPE, (LPBYTE)&v, &cb, 0) && v == PROV_RSA_AES && v == 24);

    // wyliczanie algorytmów: cztery skróty i podpis RSA
    int algs = 0; bool sha256 = false, rsa = false;
    PROV_ENUMALGS_EX e; DWORD flags = CRYPT_FIRST;
    for (cb = sizeof(e); CPGetProvParam(c.h, PP_ENUMALGS_EX, (LPBYTE)&e, &cb, flags); cb = sizeof(e), flags = 0) {
        ++algs; sha256 |= e.aiAlgid == CALG_SHA_256; rsa |= e.aiAlgid == CALG_RSA_SIGN;
    }
    CHECK(GetLastError() == ERROR_NO_MORE_ITEMS && algs == sb::hashalg::kCount + 1 && sha256 && rsa);

    // ten sam klucz pod oboma oznaczeniami; długość z certyfikatu
    for (DWORD spec : { (DWORD)AT_SIGNATURE, (DWORD)AT_KEYEXCHANGE }) {
        HCRYPTKEY k = 0;
        CHECK(CPGetUserKey(c.h, spec, &k));
        cb = sizeof(v);
        CHECK(CPGetKeyParam(c.h, k, KP_ALGID, (LPBYTE)&v, &cb, 0) && v == (DWORD)(spec == AT_SIGNATURE ? CALG_RSA_SIGN : CALG_RSA_KEYX));
        cb = sizeof(v);
        CHECK(CPGetKeyParam(c.h, k, KP_KEYLEN, (LPBYTE)&v, &cb, 0) && v == 2048);
        cb = sizeof(v);
        CHECK(CPGetKeyParam(c.h, k, KP_PERMISSIONS, (LPBYTE)&v, &cb, 0) && (v & CRYPT_EXPORT) == 0);
        CHECK(CPDestroyKey(c.h, k));
    }
    HCRYPTKEY none = 0;
    CHECK(!CPGetUserKey(c.h, 3, &none) && GetLastError() == (DWORD)NTE_NO_KEY);

    HCRYPTHASH hh = HashOf(c.h, CALG_SHA_256, kMsg, sizeof(kMsg));
    BYTE sig[256];
    // za mały bufor: rozmiar wraca, do karty nic nie idzie
    int before = g_card.calls;
    cb = 100;
    CHECK(!CPSignHash(c.h, hh, AT_SIGNATURE, NULL, 0, sig, &cb) && GetLastError() == ERROR_MORE_DATA && cb == 256);
    CHECK(g_card.calls == before);
    // anulowany PIN: kod błędu z karty bez zmian, bufor podpisu nietknięty
    memset(sig, 0xEE, sizeof(sig));
    g_card.fail = SCARD_W_CANCELLED_BY_USER;
    cb = sizeof(sig);
    CHECK(!CPSignHash(c.h, hh, AT_SIGNATURE, NULL, 0, sig, &cb) && GetLastError() == (DWORD)SCARD_W_CANCELLED_BY_USER);
    CHECK(std::all_of(sig, sig + sizeof(sig), [](BYTE b) { return b == 0xEE; }));
    // odpowiedź o złej długości (zepsuty kanał): odrzucona, program nie dostaje śmieci
    g_card.fail = ERROR_SUCCESS; g_card.shortSignature = true;
    cb = sizeof(sig);
    CHECK(!CPSignHash(c.h, hh, AT_SIGNATURE, NULL, 0, sig, &cb) && GetLastError() == (DWORD)NTE_BAD_SIGNATURE);
    CHECK(std::all_of(sig, sig + sizeof(sig), [](BYTE b) { return b == 0xEE; }));
    g_card.shortSignature = false;
    CPDestroyHash(c.h, hh);
}

// Obiekt skrótu: wartość zgodna ze wzorcem, stan po zakończeniu, kopia w trakcie liczenia
TEST(csp_hash_object_state) {
    Ctx c(NULL, CRYPT_VERIFYCONTEXT);
    CHECK(c.ok);
    if (!c.ok) return;
    HCRYPTHASH hh = HashOf(c.h, CALG_SHA_256, (const BYTE*)"ab", 2), dup = 0;
    CHECK(hh != 0);
    CHECK(CPDuplicateHash(c.h, hh, NULL, 0, &dup));
    CHECK(CPHashData(c.h, hh, (const BYTE*)"c", 1, 0) && CPHashData(c.h, dup, (const BYTE*)"c", 1, 0));
    DWORD v = 0, cb = sizeof(v);
    CHECK(CPGetHashParam(c.h, hh, HP_HASHSIZE, (LPBYTE)&v, &cb, 0) && v == 32);
    cb = sizeof(v);
    CHECK(CPGetHashParam(c.h, hh, HP_ALGID, (LPBYTE)&v, &cb, 0) && v == CALG_SHA_256);
    BYTE val[64]; cb = 0;
    CHECK(CPGetHashParam(c.h, hh, HP_HASHVAL, NULL, &cb, 0) && cb == 32);
    CHECK(CPHashData(c.h, hh, NULL, 0, 0));   // pytanie o rozmiar nie zamyka skrótu
    cb = sizeof(val);
    CHECK(CPGetHashParam(c.h, hh, HP_HASHVAL, val, &cb, 0) && cb == 32 && memcmp(val, kSha256Abc, 32) == 0);
    cb = sizeof(val);
    CHECK(CPGetHashParam(c.h, dup, HP_HASHVAL, val, &cb, 0) && cb == 32 && memcmp(val, kSha256Abc, 32) == 0);
    // po odczytaniu wartości skrót jest zamknięty
    CHECK(!CPHashData(c.h, hh, (const BYTE*)"d", 1, 0) && GetLastError() == (DWORD)NTE_BAD_HASH_STATE);
    // gotowy skrót (HP_HASHVAL): dokładnie tyle bajtów, ile ma algorytm obiektu
    HCRYPTHASH set = 0;
    CHECK(CPCreateHash(c.h, CALG_SHA_384, 0, 0, &set));
    BYTE in[64]; for (int i = 0; i < 64; ++i) in[i] = (BYTE)i;
    CHECK(CPSetHashParam(c.h, set, HP_HASHVAL, in, 0));
    cb = sizeof(val);
    CHECK(CPGetHashParam(c.h, set, HP_HASHVAL, val, &cb, 0) && cb == 48 && memcmp(val, in, 48) == 0);
    CHECK(!CPSetHashParam(c.h, set, HP_HMAC_INFO, in, 0) && GetLastError() == (DWORD)NTE_BAD_TYPE);
    CHECK(CPDestroyHash(c.h, hh) && CPDestroyHash(c.h, dup) && CPDestroyHash(c.h, set));
    CHECK(!CPDestroyHash(c.h, 0) && GetLastError() == (DWORD)NTE_BAD_HASH);
}

// Prawdziwa biblioteka przez CryptoAPI (advapi32): rejestracja jak w instalatorze, ale pod nazwą testową.
// Odtwarza zgłoszenie #64: certyfikat przypięty tylko do KSP daje staremu API „Invalid provider type specified”,
// a przypięty do CSP — klucz. Bez podpisu (nie ma kanału RDP ani karty). Wymaga administratora (HKLM).
TEST(csp_registered_dll_gives_key_to_legacy_api) {
    if (!sb::kspsetup::IsAdmin()) SKIP_ADMIN();
    const wchar_t* name = L"SignBridge Test CSP (sbtests)";
    const bool wow64 = sizeof(void*) == 4;   // testy x86: widok 32-bitowy rejestru, jak program 32-bitowy
    std::wstring dll = ExeDir() + L"\\" + sb::kspsetup::kCspDllName;
    CHECK(t::Exists(dll));
    // log prawdziwej biblioteki trafia do katalogu programu — po teście sprzątamy to, czego przedtem nie było
    std::wstring pd = sb::kspsetup::ProgramDataDir(), logs = pd + L"\\logs";
    const bool hadPd = t::Exists(pd), hadLogs = t::Exists(logs);

    CHECK(sb::kspsetup::RegisterCsp(name, dll, wow64) == ERROR_SUCCESS);
    CHECK(sb::keyprov::IsCspRegistered(name));
    HCRYPTPROV h = 0;
    CHECK(!CryptAcquireContextW(&h, NULL, name, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) && GetLastError() == (DWORD)NTE_PROV_TYPE_NO_MATCH);
    CHECK(CryptAcquireContextW(&h, NULL, name, PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
    if (h) {
        char pn[128] = {}; DWORD cb = sizeof(pn);
        CHECK(CryptGetProvParam(h, PP_NAME, (BYTE*)pn, &cb, 0) && strcmp(pn, "SignBridge Test CSP (sbtests)") == 0);
        HCRYPTHASH hh = 0; BYTE val[32]; cb = sizeof(val);
        CHECK(CryptCreateHash(h, CALG_SHA_256, 0, 0, &hh) && CryptHashData(hh, (const BYTE*)"abc", 3, 0));
        CHECK(CryptGetHashParam(hh, HP_HASHVAL, val, &cb, 0) && cb == 32 && memcmp(val, kSha256Abc, 32) == 0);
        if (hh) CryptDestroyHash(hh);
        CHECK(!CryptCreateHash(h, CALG_MD5, 0, 0, &hh) && GetLastError() == (DWORD)NTE_BAD_ALGID);
        CryptReleaseContext(h, 0);
    }

    // certyfikat testowy w magazynie Osobiste bieżącego użytkownika (usuwany na końcu)
    HCERTSTORE store = sb::certs::OpenMyStore();
    PCCERT_CONTEXT made = t::MakeTestCert(false, L"SignBridge Test (sbtests)"), cert = NULL;
    CHECK(store && made && CertAddCertificateContextToStore(store, made, CERT_STORE_ADD_REPLACE_EXISTING, &cert));
    if (cert) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hk = 0; DWORD spec = 0; BOOL freeIt = FALSE;
        // przed poprawką: tylko dostawca CNG -> stare API nie dostaje klucza
        CHECK(sb::keyprov::Bind(cert, sb::keyprov::Mode::Ksp));
        CHECK(!CryptAcquireCertificatePrivateKey(cert, 0, NULL, &hk, &spec, &freeIt) && GetLastError() == (DWORD)NTE_BAD_PROV_TYPE);
        // po poprawce: dostawca CAPI -> klucz jest i zgadza się z kluczem publicznym certyfikatu
        CHECK(sb::keyprov::Bind(cert, sb::keyprov::Mode::Csp, name));
        CHECK(CryptAcquireCertificatePrivateKey(cert, CRYPT_ACQUIRE_COMPARE_KEY_FLAG, NULL, &hk, &spec, &freeIt));
        CHECK(spec == AT_SIGNATURE);
        if (hk) {
            std::string thumb; for (wchar_t ch : sb::certs::Thumbprint(cert)) thumb += (char)ch;
            char cn[128] = {}; DWORD cb = sizeof(cn);
            CHECK(CryptGetProvParam((HCRYPTPROV)hk, PP_CONTAINER, (BYTE*)cn, &cb, 0) && thumb == cn);
            HCRYPTKEY key = 0; DWORD alg = 0; cb = sizeof(alg);
            CHECK(CryptGetUserKey((HCRYPTPROV)hk, AT_SIGNATURE, &key));
            CHECK(key && CryptGetKeyParam(key, KP_ALGID, (BYTE*)&alg, &cb, 0) && alg == CALG_RSA_SIGN);   // to sprawdza .NET Framework
            BYTE der[4096]; cb = sizeof(der);
            CHECK(key && CryptGetKeyParam(key, KP_CERTIFICATE, der, &cb, 0) && cb == cert->cbCertEncoded && memcmp(der, cert->pbCertEncoded, cb) == 0);
            HCRYPTHASH hh = 0; DWORD cbSig = 0;
            CHECK(CryptCreateHash((HCRYPTPROV)hk, CALG_SHA_256, 0, 0, &hh) && CryptSetHashParam(hh, HP_HASHVAL, kSha256Abc, 0));
            CHECK(hh && CryptSignHashW(hh, AT_SIGNATURE, NULL, 0, NULL, &cbSig) && cbSig == 256);   // sam rozmiar, bez kanału
            if (hh) CryptDestroyHash(hh);
            if (key) CryptDestroyKey(key);
            if (freeIt) CryptReleaseContext((HCRYPTPROV)hk, 0);
        }
        // programy, które wolą CNG, ale dopuszczają CAPI (dziś działają przez KSP), też dostają klucz — przez CSP
        for (DWORD flags : { (DWORD)CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, (DWORD)CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG }) {
            hk = 0; spec = 0; freeIt = FALSE;
            CHECK(CryptAcquireCertificatePrivateKey(cert, flags, NULL, &hk, &spec, &freeIt) && spec == AT_SIGNATURE);
            if (hk && freeIt) { if (spec == CERT_NCRYPT_KEY_SPEC) NCryptFreeObject(hk); else CryptReleaseContext((HCRYPTPROV)hk, 0); }
        }
        // program wyłącznie z CNG: wynik tylko do wglądu (tryb zgodności nie jest dla niego — użytkownik go wyłącza)
        hk = 0; spec = 0; freeIt = FALSE;
        BOOL onlyCng = CryptAcquireCertificatePrivateKey(cert, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &hk, &spec, &freeIt);
        std::printf("    tylko CNG przy certyfikacie w trybie zgodności: %s (0x%08lX)\n", onlyCng ? "klucz jest" : "brak klucza", onlyCng ? 0 : GetLastError());
        if (onlyCng && hk && freeIt) NCryptFreeObject(hk);
        CertDeleteCertificateFromStore(cert);   // zwalnia też kontekst
    }
    if (made) CertFreeCertificateContext(made);
    if (store) CertCloseStore(store, 0);

    CHECK(sb::kspsetup::UnregisterCsp(name, wow64) == ERROR_SUCCESS);
    CHECK(!sb::keyprov::IsCspRegistered(name));
    std::wstring log = logs + L"\\csp-sbtests-" + std::to_wstring(GetCurrentProcessId()) + L".log";
    DeleteFileW(log.c_str());
    if (!hadLogs) RemoveDirectoryW(logs.c_str());
    if (!hadPd) RemoveDirectoryW(pd.c_str());
}

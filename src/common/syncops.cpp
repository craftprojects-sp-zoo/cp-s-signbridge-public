// SignBridge — © 2026 Craftprojects Sp. z o.o. (craftprojects.pl)
// cp-signbridge — operacje po stronie serwera (implementacja)
#include "status.h"
#include "syncops.h"
#include "agentclient.h"
#include "certs.h"
#include <ncrypt.h>
#include <stdio.h>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace sb { namespace syncops {

std::wstring CertDate(const FILETIME& ft) {
    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st)) return L"";
    wchar_t b[32];
    swprintf_s(b, L"%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
    return b;
}

bool IsKspInstalled() {
    NCRYPT_PROV_HANDLE h = 0;
    if (NCryptOpenStorageProvider(&h, kProviderName, 0) != ERROR_SUCCESS) return false;
    NCryptFreeObject(h);
    return true;
}

static CertRow RowFrom(PCCERT_CONTEXT c, const wchar_t* source) {
    CertRow r;
    r.thumbprint = certs::Thumbprint(c);
    r.subject = certs::SubjectName(c);
    wchar_t iss[256] = {};
    CertGetNameStringW(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, iss, 256);
    r.issuer = iss;
    r.notAfter = CertDate(c->pCertInfo->NotAfter);
    r.source = source;
    return r;
}

SECURITY_STATUS ListAgentCerts(std::vector<CertRow>& rows, std::wstring& info, std::wstring& err) {
    AgentClient agent;
    SECURITY_STATUS s = agent.Open(L"panel", err);
    if (s != ERROR_SUCCESS) return s;
    info = agent.AgentInfo();
    proto::Certs list;
    s = agent.ListCerts(list, err);
    if (s != ERROR_SUCCESS) return s;
    for (auto& e : list.items) {
        PCCERT_CONTEXT c = CertCreateCertificateContext(X509_ASN_ENCODING, e.der.data(), (DWORD)e.der.size());
        if (!c) continue;
        rows.push_back(RowFrom(c, L"komputer użytkownika"));
        CertFreeCertificateContext(c);
    }
    return ERROR_SUCCESS;
}

void ListSyncedCerts(std::vector<CertRow>& rows) {
    HCERTSTORE store = certs::OpenMyStore();
    if (!store) return;
    PCCERT_CONTEXT c = NULL;
    while ((c = CertEnumCertificatesInStore(store, c)) != NULL) {
        std::wstring prov;
        if (!certs::HasPrivateKey(c, &prov, NULL) || !keyprov::IsOurProvider(prov)) continue;
        bool capi = _wcsicmp(prov.c_str(), keyprov::kCspName) == 0;
        rows.push_back(RowFrom(c, !certs::GetSyncMarker(c, NULL) ? L"serwer (sonda)" : capi ? L"serwer (sync, CAPI)" : L"serwer (sync)"));
    }
    CertCloseStore(store, 0);
}

SECURITY_STATUS Sync(std::vector<std::wstring>& log, int& added, int& removed) {
    added = removed = 0;
    std::wstring err;
    AgentClient agent;
    SECURITY_STATUS s = agent.Open(L"sync", err);
    if (s != ERROR_SUCCESS) { log.push_back(L"Połączenie z komputerem użytkownika: " + err); return s; }
    std::wstring info = agent.AgentInfo();
    proto::Certs list;
    s = agent.ListCerts(list, err);
    if (s != ERROR_SUCCESS) { log.push_back(L"Lista certyfikatów: " + err); return s; }
    log.push_back(L"Połączono: " + info);

    // Dostawca dla pobranych certyfikatów: wybór użytkownika (domyślnie CSP — tryb zgodności ze starszymi programami)
    std::wstring unknown;
    keyprov::Mode mode = keyprov::ReadMode(&unknown);
    if (!unknown.empty()) log.push_back(L"~ Nieznane ustawienie dostawcy „" + unknown + L"” — przyjęto tryb zgodności (CAPI); zmiana: Ustawienia.");
    bool cspOk = mode == keyprov::Mode::Csp && keyprov::IsCspRegistered();
    if (mode == keyprov::Mode::Csp && !cspOk) log.push_back(L"~ Dostawca CAPI nie jest zainstalowany — certyfikaty przypięte do dostawcy CNG.");

    HCERTSTORE store = certs::OpenMyStore();
    if (!store) { log.push_back(L"Nie można otworzyć magazynu Osobiste"); return NTE_FAIL; }
    std::vector<std::wstring> wanted;
    for (auto& e : list.items) {
        PCCERT_CONTEXT c = CertCreateCertificateContext(X509_ASN_ENCODING, e.der.data(), (DWORD)e.der.size());
        if (!c) continue;
        std::wstring thumb = certs::Thumbprint(c);
        wanted.push_back(thumb);
        keyprov::Mode bind = keyprov::Effective(c, mode, cspOk);
        keyprov::Bind(c, bind);
        certs::SetSyncMarker(c, info);
        PCCERT_CONTEXT stored = NULL;
        if (CertAddCertificateContextToStore(store, c, CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES, &stored)) {
            keyprov::Bind(stored, bind);
            certs::SetSyncMarker(stored, info);
            CertFreeCertificateContext(stored);
            log.push_back(L"+ " + certs::SubjectName(c) + L"  (" + thumb.substr(0, 8) + L"…)");
            ++added;
        } else {
            log.push_back(L"! " + certs::SubjectName(c) + L": błąd " + std::to_wstring(GetLastError()));
        }
        CertFreeCertificateContext(c);
    }
    std::vector<PCCERT_CONTEXT> toDelete;
    PCCERT_CONTEXT c = NULL;
    while ((c = CertEnumCertificatesInStore(store, c)) != NULL) {
        if (!certs::GetSyncMarker(c, NULL)) continue;
        std::wstring t = certs::Thumbprint(c);
        bool keep = false;
        for (auto& w : wanted) if (w == t) { keep = true; break; }
        if (!keep) toDelete.push_back(CertDuplicateCertificateContext(c));
    }
    for (auto d : toDelete) { log.push_back(L"- " + certs::SubjectName(d) + L" (nieaktualny)"); CertDeleteCertificateFromStore(d); ++removed; }
    CertCloseStore(store, 0);
    return ERROR_SUCCESS;
}

bool SetKeyProviderMode(keyprov::Mode mode, std::vector<std::wstring>& log) {
    // najpierw magazyn, potem zapis wyboru: przy błędzie nie zostaje ustawienie, którego nie zastosowano
    HCERTSTORE store = certs::OpenMyStore();
    if (!store) { log.push_back(L"Nie można otworzyć magazynu Osobiste"); return false; }
    if (!keyprov::WriteMode(mode)) { CertCloseStore(store, 0); log.push_back(L"Nie udało się zapisać ustawienia dostawcy."); return false; }
    bool cspOk = mode == keyprov::Mode::Csp && keyprov::IsCspRegistered();
    int n = keyprov::Rebind(store, mode, cspOk, &log);
    CertCloseStore(store, 0);
    if (mode == keyprov::Mode::Csp && !cspOk) log.push_back(L"Dostawca CAPI nie jest zainstalowany na tym serwerze — certyfikaty zostają przy dostawcy CNG.");
    log.push_back((mode == keyprov::Mode::Csp ? L"Tryb zgodności ze starszymi programami (CAPI): włączony" : L"Tryb zgodności ze starszymi programami (CAPI): wyłączony")
                  + std::wstring(L" — przestawiono certyfikatów: ") + std::to_wstring(n));
    return true;
}

int Unsync() {
    HCERTSTORE store = certs::OpenMyStore();
    if (!store) return 0;
    std::vector<PCCERT_CONTEXT> toDelete;
    PCCERT_CONTEXT c = NULL;
    while ((c = CertEnumCertificatesInStore(store, c)) != NULL) if (certs::GetSyncMarker(c, NULL)) toDelete.push_back(CertDuplicateCertificateContext(c));
    for (auto d : toDelete) CertDeleteCertificateFromStore(d);
    CertCloseStore(store, 0);
    return (int)toDelete.size();
}

// Test podpisu drogą CryptoAPI (CryptCreateHash + HP_HASHVAL + CryptSignHash) — tak podpisuje starszy program.
// Wynik sprawdzamy kluczem publicznym certyfikatu niezależnie od naszego dostawcy: CAPI oddaje podpis
// little-endian, więc do weryfikacji w CNG odwracamy bajty.
static SECURITY_STATUS TestSignCapi(PCCERT_CONTEXT cert, HCRYPTPROV hProv, DWORD spec, const BYTE* hash, DWORD cbHash, std::vector<std::wstring>& log) {
    HCRYPTHASH hh = 0;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hh)) { DWORD e = GetLastError(); log.push_back(L"CryptCreateHash: " + ErrorText((LONG)e)); return (SECURITY_STATUS)e; }
    SECURITY_STATUS s = ERROR_SUCCESS;
    BYTE sig[1024]; DWORD cbSig = sizeof(sig);
    if (!CryptSetHashParam(hh, HP_HASHVAL, hash, 0)) { s = (SECURITY_STATUS)GetLastError(); log.push_back(L"CryptSetHashParam: " + ErrorText(s)); }
    else {
        log.push_back(L"Podpisuję przez kanał… (PIN na komputerze użytkownika)");
        ULONGLONG t0 = GetTickCount64();
        if (!CryptSignHashW(hh, spec, NULL, 0, sig, &cbSig)) s = (SECURITY_STATUS)GetLastError();
        wchar_t b[64]; swprintf_s(b, L" (%lu B, %llu ms)", cbSig, GetTickCount64() - t0);
        log.push_back(L"Podpis: " + ErrorText(s) + (s == ERROR_SUCCESS ? b : L""));
    }
    CryptDestroyHash(hh);
    if (s != ERROR_SUCCESS) return s;
    for (DWORD i = 0; i < cbSig / 2; ++i) { BYTE t = sig[i]; sig[i] = sig[cbSig - 1 - i]; sig[cbSig - 1 - i] = t; }
    BCRYPT_KEY_HANDLE pub = NULL; std::wstring alg; DWORD bits = 0;
    if (!certs::ImportPublicKey(cert, &pub, alg, bits)) { log.push_back(L"Weryfikacja: nie można odczytać klucza publicznego certyfikatu"); return NTE_FAIL; }
    BCRYPT_PKCS1_PADDING_INFO pad = { BCRYPT_SHA256_ALGORITHM };
    NTSTATUS v = BCryptVerifySignature(pub, &pad, (PUCHAR)hash, cbHash, sig, cbSig, BCRYPT_PAD_PKCS1);
    BCryptDestroyKey(pub);
    log.push_back(L"Weryfikacja: " + ErrorText(v));
    return BCRYPT_SUCCESS(v) ? ERROR_SUCCESS : NTE_BAD_SIGNATURE;
}

SECURITY_STATUS TestSign(const std::wstring& thumbprint, std::vector<std::wstring>& log) {
    HCERTSTORE store = certs::OpenMyStore();
    if (!store) return NTE_FAIL;
    PCCERT_CONTEXT cert = NULL;
    if (!thumbprint.empty()) cert = certs::FindByThumbprint(store, thumbprint);
    else {
        PCCERT_CONTEXT c = NULL;
        while ((c = CertEnumCertificatesInStore(store, c)) != NULL) if (certs::GetSyncMarker(c, NULL)) { cert = CertDuplicateCertificateContext(c); CertFreeCertificateContext(c); break; }
    }
    if (!cert) { CertCloseStore(store, 0); log.push_back(L"Brak zsynchronizowanego certyfikatu — najpierw pobierz certyfikaty."); return NTE_NOT_FOUND; }
    log.push_back(L"Certyfikat: " + certs::SubjectName(cert));

    // Certyfikat w trybie zgodności: ta sama droga co starszy program (CryptoAPI); inaczej CNG jak dotąd
    keyprov::Mode bound = keyprov::Mode::Ksp;
    bool capi = keyprov::BoundTo(cert, &bound) && bound == keyprov::Mode::Csp;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hk = 0; DWORD spec = 0; BOOL freeIt = FALSE;
    if (!CryptAcquireCertificatePrivateKey(cert, capi ? 0 : CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &hk, &spec, &freeIt)) {
        DWORD e = GetLastError();
        log.push_back(L"Otwarcie klucza: " + ErrorText((LONG)e));
        CertFreeCertificateContext(cert); CertCloseStore(store, 0);
        return (SECURITY_STATUS)e;
    }
    BYTE hash[32]; for (int i = 0; i < 32; ++i) hash[i] = (BYTE)(i * 13 + 7);
    if (capi) {
        log.push_back(std::wstring(L"Dostawca: ") + keyprov::kCspName + L" (CAPI)");
        SECURITY_STATUS cs = TestSignCapi(cert, (HCRYPTPROV)hk, spec, hash, sizeof(hash), log);
        if (freeIt) CryptReleaseContext((HCRYPTPROV)hk, 0);
        CertFreeCertificateContext(cert); CertCloseStore(store, 0);
        return cs;
    }
    BCRYPT_PKCS1_PADDING_INFO pad = { BCRYPT_SHA256_ALGORITHM };
    BYTE sig[1024]; DWORD cbSig = 0;
    log.push_back(L"Podpisuję przez kanał… (PIN na komputerze użytkownika)");
    ULONGLONG t0 = GetTickCount64();
    SECURITY_STATUS s = NCryptSignHash((NCRYPT_KEY_HANDLE)hk, &pad, hash, 32, sig, sizeof(sig), &cbSig, NCRYPT_PAD_PKCS1_FLAG);
    wchar_t b[64]; swprintf_s(b, L" (%lu B, %llu ms)", cbSig, GetTickCount64() - t0);
    log.push_back(L"Podpis: " + ErrorText(s) + (s == ERROR_SUCCESS ? b : L""));
    if (s == ERROR_SUCCESS) {
        SECURITY_STATUS v = NCryptVerifySignature((NCRYPT_KEY_HANDLE)hk, &pad, hash, 32, sig, cbSig, NCRYPT_PAD_PKCS1_FLAG);
        log.push_back(L"Weryfikacja: " + ErrorText(v));
        if (v != ERROR_SUCCESS) s = v;
    }
    if (freeIt) NCryptFreeObject(hk);
    CertFreeCertificateContext(cert); CertCloseStore(store, 0);
    return s;
}

}}  // namespace sb::syncops

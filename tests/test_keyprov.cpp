// SignBridge — © 2026 Craftprojects Sp. z o.o. (craftprojects.pl)
// Powiązanie certyfikatu z dostawcą (keyprov): ustawienie użytkownika, przełączenie CSP <-> KSP i powrót
#include "check.h"
#include "testcert.h"
#include "keyprov.h"
#include "certs.h"

using namespace sb::keyprov;

namespace {

struct Kpi { bool ok = false; std::wstring container, provider; DWORD type = 0, flags = 0, params = 0, keySpec = 0; };

bool operator==(const Kpi& a, const Kpi& b) {
    return a.ok == b.ok && a.container == b.container && a.provider == b.provider && a.type == b.type && a.flags == b.flags &&
           a.params == b.params && a.keySpec == b.keySpec;
}

// CERT_KEY_PROV_INFO certyfikatu o podanym odcisku, czytane z magazynu na nowo
Kpi ReadKpi(HCERTSTORE store, const std::wstring& thumb) {
    Kpi k;
    PCCERT_CONTEXT c = sb::certs::FindByThumbprint(store, thumb);
    if (!c) return k;
    DWORD cb = 0;
    if (CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb)) {
        std::vector<BYTE> buf(cb);
        if (CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, buf.data(), &cb)) {
            auto* p = (CRYPT_KEY_PROV_INFO*)buf.data();
            k.ok = true;
            k.container = p->pwszContainerName ? p->pwszContainerName : L"";
            k.provider = p->pwszProvName ? p->pwszProvName : L"";
            k.type = p->dwProvType; k.flags = p->dwFlags; k.params = p->cProvParam; k.keySpec = p->dwKeySpec;
        }
    }
    CertFreeCertificateContext(c);
    return k;
}

// Dodaje certyfikat do magazynu w pamięci; zwraca odcisk
std::wstring AddCert(HCERTSTORE store, bool ec, const wchar_t* cn, bool synced) {
    PCCERT_CONTEXT cert = t::MakeTestCert(ec, cn);
    if (!cert) return L"";
    PCCERT_CONTEXT stored = NULL;
    std::wstring thumb;
    if (CertAddCertificateContextToStore(store, cert, CERT_STORE_ADD_ALWAYS, &stored)) {
        thumb = sb::certs::Thumbprint(stored);
        if (synced) { Bind(stored, Mode::Ksp); sb::certs::SetSyncMarker(stored, L"test@komputer"); }
        CertFreeCertificateContext(stored);
    }
    CertFreeCertificateContext(cert);
    return thumb;
}

}  // namespace

// Brak ustawienia = tryb zgodności (CSP); wybór użytkownika zapisuje się w jego gałęzi rejestru i wraca
TEST(keyprov_mode_default_csp_and_roundtrip) {
    std::wstring key = L"Software\\cp-signbridge-sbtests-" + std::to_wstring(GetCurrentProcessId());
    RegDeleteTreeW(HKEY_CURRENT_USER, key.c_str());
    std::wstring unknown = L"x";
    CHECK(ReadMode(&unknown, HKEY_CURRENT_USER, key.c_str()) == Mode::Csp);
    CHECK(unknown.empty());
    CHECK(WriteMode(Mode::Ksp, HKEY_CURRENT_USER, key.c_str()));
    CHECK(ReadMode(&unknown, HKEY_CURRENT_USER, key.c_str()) == Mode::Ksp && unknown.empty());
    CHECK(WriteMode(Mode::Csp, HKEY_CURRENT_USER, key.c_str()));
    CHECK(ReadMode(&unknown, HKEY_CURRENT_USER, key.c_str()) == Mode::Csp && unknown.empty());

    // nieznana wartość: działamy w trybie domyślnym, ale wartości nie nadpisujemy po cichu — wraca do logu
    HKEY h;
    CHECK(RegOpenKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, KEY_READ | KEY_WRITE, &h) == ERROR_SUCCESS);
    const wchar_t bad[] = L"cos-innego";
    RegSetValueExW(h, kCfgValue, 0, REG_SZ, (const BYTE*)bad, sizeof(bad));
    CHECK(ReadMode(&unknown, HKEY_CURRENT_USER, key.c_str()) == Mode::Csp);
    CHECK(unknown == bad);
    wchar_t now[32] = {}; DWORD cb = sizeof(now);
    CHECK(RegQueryValueExW(h, kCfgValue, NULL, NULL, (BYTE*)now, &cb) == ERROR_SUCCESS && std::wstring(now) == bad);
    RegCloseKey(h);
    RegDeleteTreeW(HKEY_CURRENT_USER, key.c_str());
    RegDeleteKeyW(HKEY_CURRENT_USER, key.c_str());
}

// Przełącznik: KSP -> CSP -> KSP. Zmienia tylko certyfikaty pobrane przez SignBridge, ECDSA zostaje przy KSP,
// a powrót odtwarza poprzedni wpis CERT_KEY_PROV_INFO co do pola.
TEST(keyprov_switch_csp_ksp_and_back) {
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    CHECK(store != NULL);
    if (!store) return;
    std::wstring rsa = AddCert(store, false, L"SignBridge Test RSA", true);
    std::wstring ec = AddCert(store, true, L"SignBridge Test ECDSA", true);
    std::wstring foreign = AddCert(store, false, L"SignBridge Test Cudzy", false);
    CHECK(!rsa.empty() && !ec.empty() && !foreign.empty());
    if (rsa.empty() || ec.empty() || foreign.empty()) { CertCloseStore(store, 0); return; }

    // cudzy certyfikat (bez markera sync) z własnym dostawcą — nie nasz, nie wolno go ruszyć
    PCCERT_CONTEXT f = sb::certs::FindByThumbprint(store, foreign);
    CRYPT_KEY_PROV_INFO other = {};
    other.pwszContainerName = (LPWSTR)L"cudzy-kontener";
    other.pwszProvName = (LPWSTR)MS_ENH_RSA_AES_PROV_W;
    other.dwProvType = PROV_RSA_AES;
    other.dwKeySpec = AT_KEYEXCHANGE;
    CHECK(f && CertSetCertificateContextProperty(f, CERT_KEY_PROV_INFO_PROP_ID, 0, &other));
    if (f) CertFreeCertificateContext(f);

    const Kpi rsaKsp = ReadKpi(store, rsa), ecKsp = ReadKpi(store, ec), foreignBefore = ReadKpi(store, foreign);
    CHECK(rsaKsp.ok && rsaKsp.provider == kKspName && rsaKsp.type == 0 && rsaKsp.keySpec == 0 && rsaKsp.container == rsa);

    // KSP -> CSP
    std::vector<std::wstring> log;
    CHECK(Rebind(store, Mode::Csp, true, &log) == 1);
    Kpi k = ReadKpi(store, rsa);
    CHECK(k.ok && k.provider == kCspName && k.type == PROV_RSA_AES && k.type == 24 && k.keySpec == AT_SIGNATURE);
    CHECK(k.container == rsa && k.flags == 0 && k.params == 0);
    CHECK(ReadKpi(store, ec) == ecKsp);                 // CAPI nie zna ECDSA: zostaje dostawca CNG
    CHECK(ReadKpi(store, foreign) == foreignBefore);
    CHECK(log.size() == 1);
    CHECK(Rebind(store, Mode::Csp, true, NULL) == 0);   // drugi raz: nic do zrobienia

    PCCERT_CONTEXT c = sb::certs::FindByThumbprint(store, rsa);
    Mode m = Mode::Ksp;
    CHECK(c && BoundTo(c, &m) && m == Mode::Csp);
    if (c) CertFreeCertificateContext(c);

    // CSP -> KSP: wpis jak przed przełączeniem
    CHECK(Rebind(store, Mode::Ksp, true, NULL) == 1);
    CHECK(ReadKpi(store, rsa) == rsaKsp);
    CHECK(ReadKpi(store, ec) == ecKsp);
    CHECK(ReadKpi(store, foreign) == foreignBefore);

    // tryb zgodności wybrany, ale dostawcy CAPI nie ma na serwerze: certyfikaty zostają przy KSP
    CHECK(Rebind(store, Mode::Csp, false, NULL) == 0);
    CHECK(ReadKpi(store, rsa) == rsaKsp);

    // cudzy certyfikat nie jest „nasz”
    f = sb::certs::FindByThumbprint(store, foreign);
    CHECK(f && !BoundTo(f, &m));
    if (f) CertFreeCertificateContext(f);
    CertCloseStore(store, 0);
}

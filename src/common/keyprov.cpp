// SignBridge — © 2026 Craftprojects Sp. z o.o. (craftprojects.pl)
// cp-signbridge — powiązanie certyfikatu z dostawcą CSP albo KSP (implementacja)
#include "keyprov.h"
#include "certs.h"
#include <string.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace sb { namespace keyprov {

Mode ReadMode(std::wstring* unknown, HKEY root, const wchar_t* subkey) {
    if (unknown) unknown->clear();
    HKEY h;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &h) != ERROR_SUCCESS) return Mode::Csp;
    wchar_t buf[32] = {}; DWORD cb = sizeof(buf) - sizeof(wchar_t), type = 0;
    LONG r = RegQueryValueExW(h, kCfgValue, NULL, &type, (BYTE*)buf, &cb);
    RegCloseKey(h);
    if (r == ERROR_FILE_NOT_FOUND) return Mode::Csp;
    if (r == ERROR_SUCCESS && type == REG_SZ) {
        if (_wcsicmp(buf, L"ksp") == 0) return Mode::Ksp;
        if (_wcsicmp(buf, L"csp") == 0) return Mode::Csp;
    }
    if (unknown) *unknown = (r == ERROR_SUCCESS && type == REG_SZ) ? buf : L"(nieczytelna wartość)";
    return Mode::Csp;
}

bool WriteMode(Mode mode, HKEY root, const wchar_t* subkey) {
    HKEY h;
    if (RegCreateKeyExW(root, subkey, 0, NULL, 0, KEY_WRITE, NULL, &h, NULL) != ERROR_SUCCESS) return false;
    const wchar_t* v = mode == Mode::Csp ? L"csp" : L"ksp";
    LONG r = RegSetValueExW(h, kCfgValue, 0, REG_SZ, (const BYTE*)v, (DWORD)((wcslen(v) + 1) * sizeof(wchar_t)));
    RegCloseKey(h);
    return r == ERROR_SUCCESS;
}

bool IsCspRegistered(const wchar_t* name) {
    HCRYPTPROV h = 0;
    if (!CryptAcquireContextW(&h, NULL, name, kCspProvType, CRYPT_VERIFYCONTEXT)) return false;
    CryptReleaseContext(h, 0);
    return true;
}

Mode Effective(PCCERT_CONTEXT cert, Mode wanted, bool cspAvailable) {
    if (wanted != Mode::Csp || !cspAvailable) return Mode::Ksp;
    const char* oid = cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    return (oid && strcmp(oid, szOID_RSA_RSA) == 0) ? Mode::Csp : Mode::Ksp;
}

bool Bind(PCCERT_CONTEXT cert, Mode mode, const wchar_t* cspName) {
    std::wstring thumb = certs::Thumbprint(cert);
    if (thumb.empty()) return false;
    CRYPT_KEY_PROV_INFO kpi = {};
    kpi.pwszContainerName = (LPWSTR)thumb.c_str();
    if (mode == Mode::Csp) {
        kpi.pwszProvName = (LPWSTR)cspName;
        kpi.dwProvType = kCspProvType;
        kpi.dwKeySpec = kCspKeySpec;
    } else {
        kpi.pwszProvName = (LPWSTR)kKspName;   // dwProvType 0 = dostawca CNG, dwKeySpec 0
    }
    return CertSetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi) == TRUE;
}

bool BoundTo(PCCERT_CONTEXT cert, Mode* mode, const wchar_t* cspName) {
    std::wstring prov; DWORD type = 0;
    if (!certs::HasPrivateKey(cert, &prov, &type)) return false;
    if (type == 0 && _wcsicmp(prov.c_str(), kKspName) == 0) { if (mode) *mode = Mode::Ksp; return true; }
    if (type == kCspProvType && _wcsicmp(prov.c_str(), cspName) == 0) { if (mode) *mode = Mode::Csp; return true; }
    return false;
}

int Rebind(HCERTSTORE store, Mode wanted, bool cspAvailable, std::vector<std::wstring>* log) {
    // najpierw lista, potem zmiany — nie zmieniamy właściwości w trakcie wyliczania magazynu
    std::vector<PCCERT_CONTEXT> ours;
    PCCERT_CONTEXT c = NULL;
    while ((c = CertEnumCertificatesInStore(store, c)) != NULL)
        if (certs::GetSyncMarker(c, NULL)) ours.push_back(CertDuplicateCertificateContext(c));
    int changed = 0;
    for (PCCERT_CONTEXT cert : ours) {
        Mode target = Effective(cert, wanted, cspAvailable), now = Mode::Ksp;
        if (!BoundTo(cert, &now) || now != target) {
            bool ok = Bind(cert, target);
            if (ok) ++changed;
            if (log) log->push_back((ok ? L"+ " : L"! ") + certs::SubjectName(cert) + (target == Mode::Csp ? L": tryb zgodności (CAPI)" : L": dostawca CNG"));
        }
        CertFreeCertificateContext(cert);
    }
    return changed;
}

}}  // namespace sb::keyprov

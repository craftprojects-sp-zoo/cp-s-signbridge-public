// SignBridge — © 2026 Craftprojects Sp. z o.o. (craftprojects.pl)
// cp-signbridge — do którego dostawcy przypięty jest certyfikat użytkownika na serwerze (CERT_KEY_PROV_INFO):
//   CSP (CryptoAPI, „tryb zgodności”) — starsze programy pobierające klucz starym API, np. .NET Framework
//                                        X509Certificate2.PrivateKey (Symfonia); typ dostawcy 24, AT_SIGNATURE
//   KSP (CNG)                          — powiązanie sprzed 1.2.0; typ dostawcy 0
// Wybiera użytkownik dla swojego konta (HKCU, bez administratora); domyślnie CSP — docs/decisions/D-0001.
// Certyfikaty z kluczem innym niż RSA zostają przy KSP (CAPI nie zna ECDSA).
#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>

namespace sb { namespace keyprov {

const wchar_t* const kKspName = L"SignBridge Key Storage Provider";
const wchar_t* const kCspName = L"SignBridge Cryptographic Provider";
const DWORD kCspProvType = PROV_RSA_AES;   // 24: RSA + SHA-2
const DWORD kCspKeySpec = AT_SIGNATURE;

const wchar_t* const kCfgKey = L"Software\\cp-signbridge";
const wchar_t* const kCfgValue = L"KeyProvider";   // "csp" | "ksp"

enum class Mode { Csp, Ksp };

inline bool IsOurProvider(const std::wstring& name) {
    return _wcsicmp(name.c_str(), kKspName) == 0 || _wcsicmp(name.c_str(), kCspName) == 0;
}

// Wybór użytkownika. Brak wartości = CSP. Nieznana wartość: też CSP, ale niczego nie nadpisujemy —
// tekst z rejestru wraca w *unknown, żeby wywołujący mógł go zapisać w logu.
Mode ReadMode(std::wstring* unknown = nullptr, HKEY root = HKEY_CURRENT_USER, const wchar_t* subkey = kCfgKey);
bool WriteMode(Mode mode, HKEY root = HKEY_CURRENT_USER, const wchar_t* subkey = kCfgKey);

// Czy Windows umie załadować dostawcę CAPI o tej nazwie (w architekturze bieżącego procesu)
bool IsCspRegistered(const wchar_t* name = kCspName);

// Dostawca dla konkretnego certyfikatu: CSP tylko dla kluczy RSA i tylko, gdy CSP jest zainstalowany
Mode Effective(PCCERT_CONTEXT cert, Mode wanted, bool cspAvailable);

// Ustawia CERT_KEY_PROV_INFO (kontener = odcisk SHA-1 certyfikatu). Wpis zależy tylko od trybu i odcisku,
// więc powrót do poprzedniego trybu odtwarza poprzedni wpis co do pola.
bool Bind(PCCERT_CONTEXT cert, Mode mode, const wchar_t* cspName = kCspName);

// false: certyfikat nie jest przypięty do żadnego z naszych dostawców
bool BoundTo(PCCERT_CONTEXT cert, Mode* mode, const wchar_t* cspName = kCspName);

// Przestawia certyfikaty pobrane z komputera użytkownika (marker sync) w podanym magazynie.
// Innych certyfikatów nie dotyka. Zwraca liczbę zmienionych wpisów.
int Rebind(HCERTSTORE store, Mode wanted, bool cspAvailable, std::vector<std::wstring>* log = nullptr);

}}  // namespace sb::keyprov

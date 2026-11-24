// SignBridge — © 2026 Craftprojects Sp. z o.o. (craftprojects.pl)
// cp-signbridge — dostawca CryptoAPI (CSP), cpsignbridge-csp.dll: funkcje wołane przez Windows (advapi32)
//
// Deklaracje punktów wejścia CSP są w Cryptographic Service Provider Development Kit (cspdk.h), którego
// nie ma w Windows SDK — stąd własne, zgodne z dokumentacją Microsoft („CryptoSPI Functions”).
#pragma once
#include <windows.h>
#include <wincrypt.h>

namespace sb { class IBackend; }

typedef struct _VTableProvStruc {
    DWORD   Version;
    FARPROC FuncVerifyImage;
    FARPROC FuncReturnhWnd;
    DWORD   dwProvType;      // od wersji 2
    BYTE*   pbContextInfo;
    DWORD   cbContextInfo;
    LPSTR   pszProvName;     // od wersji 3: nazwa, pod którą dostawcę zarejestrowano
} VTableProvStruc, *PVTableProvStruc;

extern "C" {
BOOL WINAPI CPAcquireContext(HCRYPTPROV* phProv, LPCSTR szContainer, DWORD dwFlags, PVTableProvStruc pVTable);
BOOL WINAPI CPReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);
BOOL WINAPI CPGetProvParam(HCRYPTPROV hProv, DWORD dwParam, LPBYTE pbData, LPDWORD pcbDataLen, DWORD dwFlags);
BOOL WINAPI CPSetProvParam(HCRYPTPROV hProv, DWORD dwParam, const BYTE* pbData, DWORD dwFlags);
BOOL WINAPI CPGenRandom(HCRYPTPROV hProv, DWORD cbLen, LPBYTE pbBuffer);
BOOL WINAPI CPGetUserKey(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY* phUserKey);
BOOL WINAPI CPGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey);
BOOL WINAPI CPDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hHash, DWORD dwFlags, HCRYPTKEY* phKey);
BOOL WINAPI CPDuplicateKey(HCRYPTPROV hProv, HCRYPTKEY hKey, LPDWORD pdwReserved, DWORD dwFlags, HCRYPTKEY* phKey);
BOOL WINAPI CPDestroyKey(HCRYPTPROV hProv, HCRYPTKEY hKey);
BOOL WINAPI CPGetKeyParam(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, LPBYTE pbData, LPDWORD pcbDataLen, DWORD dwFlags);
BOOL WINAPI CPSetKeyParam(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, const BYTE* pbData, DWORD dwFlags);
BOOL WINAPI CPExportKey(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTKEY hPubKey, DWORD dwBlobType, DWORD dwFlags, LPBYTE pbData, LPDWORD pcbDataLen);
BOOL WINAPI CPImportKey(HCRYPTPROV hProv, const BYTE* pbData, DWORD cbDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey);
BOOL WINAPI CPEncrypt(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL fFinal, DWORD dwFlags, LPBYTE pbData, LPDWORD pcbDataLen, DWORD cbBufLen);
BOOL WINAPI CPDecrypt(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL fFinal, DWORD dwFlags, LPBYTE pbData, LPDWORD pcbDataLen);
BOOL WINAPI CPCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash);
BOOL WINAPI CPDuplicateHash(HCRYPTPROV hProv, HCRYPTHASH hHash, LPDWORD pdwReserved, DWORD dwFlags, HCRYPTHASH* phHash);
BOOL WINAPI CPHashData(HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE* pbData, DWORD cbDataLen, DWORD dwFlags);
BOOL WINAPI CPHashSessionKey(HCRYPTPROV hProv, HCRYPTHASH hHash, HCRYPTKEY hKey, DWORD dwFlags);
BOOL WINAPI CPSetHashParam(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, const BYTE* pbData, DWORD dwFlags);
BOOL WINAPI CPGetHashParam(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, LPBYTE pbData, LPDWORD pcbDataLen, DWORD dwFlags);
BOOL WINAPI CPDestroyHash(HCRYPTPROV hProv, HCRYPTHASH hHash);
BOOL WINAPI CPSignHash(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwKeySpec, LPCWSTR szDescription, DWORD dwFlags, LPBYTE pbSignature, LPDWORD pcbSigLen);
BOOL WINAPI CPVerifySignature(HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE* pbSignature, DWORD cbSigLen, HCRYPTKEY hPubKey, LPCWSTR szDescription, DWORD dwFlags);
}

namespace sb { namespace csp {

// Testy: backend zamiast kanału RDP (nullptr przywraca właściwy). Wywołać przed pierwszym CPAcquireContext.
void SetBackendForTests(IBackend* backend);

}}  // namespace sb::csp

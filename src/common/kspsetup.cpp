// SignBridge — © 2026 Craftprojects Sp. z o.o. (craftprojects.pl)
// cp-signbridge — instalacja po stronie serwera (implementacja)
#include "status.h"
#include "kspsetup.h"
#include "keyprov.h"
#include <bcrypt.h>
#include <ncrypt.h>
#include <shlobj.h>
#include <aclapi.h>
#include <sddl.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")

namespace sb { namespace kspsetup {
namespace {

// Funkcje rejestracji dostawców są eksportowane z bcrypt.dll, ale zadeklarowane tylko w CPDK.
typedef NTSTATUS (WINAPI *PFN_BCryptRegisterProvider)(LPCWSTR, ULONG, PCRYPT_PROVIDER_REG);
typedef NTSTATUS (WINAPI *PFN_BCryptUnregisterProvider)(LPCWSTR);
typedef NTSTATUS (WINAPI *PFN_BCryptAddContextFunctionProvider)(ULONG, LPCWSTR, ULONG, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *PFN_BCryptRemoveContextFunctionProvider)(ULONG, LPCWSTR, ULONG, LPCWSTR, LPCWSTR);

struct BCryptReg {
    PFN_BCryptRegisterProvider Register = nullptr;
    PFN_BCryptUnregisterProvider Unregister = nullptr;
    PFN_BCryptAddContextFunctionProvider AddCtx = nullptr;
    PFN_BCryptRemoveContextFunctionProvider RemoveCtx = nullptr;
    bool Load() {
        HMODULE h = LoadLibraryW(L"bcrypt.dll");
        if (!h) return false;
        Register = (PFN_BCryptRegisterProvider)GetProcAddress(h, "BCryptRegisterProvider");
        Unregister = (PFN_BCryptUnregisterProvider)GetProcAddress(h, "BCryptUnregisterProvider");
        AddCtx = (PFN_BCryptAddContextFunctionProvider)GetProcAddress(h, "BCryptAddContextFunctionProvider");
        RemoveCtx = (PFN_BCryptRemoveContextFunctionProvider)GetProcAddress(h, "BCryptRemoveContextFunctionProvider");
        return Register && Unregister && AddCtx && RemoveCtx;
    }
};

const wchar_t* const kDllName = L"cpsignbridge.dll";
const wchar_t* const kCspRegRoot = L"SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\";
const wchar_t* const kRunValue = L"cp-signbridge-panel";
const wchar_t* const kRunKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";

// Prawa katalogów (SDDL), chronione (P) — bez dziedziczenia z ProgramData, które domyślnie pozwala
// zwykłym użytkownikom zakładać pliki i katalogi. Właściciel: Administratorzy.
//   dane: SYSTEM i Administratorzy — pełne; Authenticated Users — odczyt (install.log czyta panel)
//   logs: użytkownicy tylko listują katalog i zakładają w nim pliki (bez podkatalogów, więc bez
//         junction); pełne prawa do pliku ma tylko jego właściciel (CREATOR OWNER) i administratorzy
//   pkg:  wyłącznie SYSTEM i Administratorzy
const wchar_t* const kSddlData = L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)";
const wchar_t* const kSddlLogs = L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200ab;;;AU)(A;OICIIO;FA;;;CO)";
const wchar_t* const kSddlPkg  = L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

bool FileExists(const std::wstring& p) { return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES; }

std::wstring SysDir(bool wow64) {
    wchar_t win[MAX_PATH];
    GetWindowsDirectoryW(win, MAX_PATH);
    return std::wstring(win) + (wow64 ? L"\\SysWOW64" : L"\\System32");
}

std::wstring Folder(int csidl) {
    wchar_t buf[MAX_PATH] = {};
    SHGetFolderPathW(NULL, csidl, NULL, SHGFP_TYPE_CURRENT, buf);
    return buf;
}

std::wstring Version(const std::wstring& path) {
    DWORD h = 0;
    DWORD cb = GetFileVersionInfoSizeW(path.c_str(), &h);
    if (!cb) return L"";
    std::wstring buf(cb, L'\0');
    if (!GetFileVersionInfoW(path.c_str(), 0, cb, &buf[0])) return L"";
    VS_FIXEDFILEINFO* ffi = nullptr; UINT len = 0;
    if (!VerQueryValueW(&buf[0], L"\\", (LPVOID*)&ffi, &len) || !ffi) return L"";
    wchar_t v[64];
    swprintf_s(v, L"%u.%u.%u.%u", HIWORD(ffi->dwFileVersionMS), LOWORD(ffi->dwFileVersionMS), HIWORD(ffi->dwFileVersionLS), LOWORD(ffi->dwFileVersionLS));
    return v;
}

bool IsReparse(DWORD a) { return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT) != 0; }

// Usuwa samo dowiązanie (junction, symlink) albo plik — nigdy cel dowiązania
void RemoveLink(const std::wstring& p, DWORD attrs) {
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) RemoveDirectoryW(p.c_str()); else DeleteFileW(p.c_str());
}

void EnablePrivilege(const wchar_t* name) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    if (LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid)) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    }
    CloseHandle(tok);
}

// Właściciel i lista praw z SDDL na samym katalogu: przez uchwyt otwarty bez podążania za dowiązaniem,
// bez rozpropagowania na zawartość (zawartość porządkuje SecureDataDir). Zamiast icacls — bez procesu
// potomnego, więc nie da się podstawić icacls.exe obok instalatora.
DWORD SetDirSecurity(const std::wstring& dir, const wchar_t* sddl) {
    HANDLE h = CreateFileW(dir.c_str(), READ_CONTROL | WRITE_DAC | WRITE_OWNER, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE) return GetLastError();
    DWORD e = ERROR_SUCCESS;
    BY_HANDLE_FILE_INFORMATION fi = {};
    if (!GetFileInformationByHandle(h, &fi)) e = GetLastError();
    else if (!(fi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (fi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) e = ERROR_CANT_ACCESS_FILE;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (e == ERROR_SUCCESS && !ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL)) e = GetLastError();
    if (e == ERROR_SUCCESS && !SetKernelObjectSecurity(h, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd))
        e = GetLastError();
    if (sd) LocalFree(sd);
    CloseHandle(h);
    return e;
}

// Plik: prawa wyłącznie dziedziczone z katalogu (zdejmuje wpisy jawne, np. Modify z 1.0.0).
// Dodatkowe dowiązanie twarde (plik współdzielony z innym miejscem dysku) — usuwa tylko tę nazwę.
DWORD ResetFileSecurity(const std::wstring& p) {
    HANDLE h = CreateFileW(p.c_str(), READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE) return GetLastError();
    BY_HANDLE_FILE_INFORMATION fi = {};
    BOOL ok = GetFileInformationByHandle(h, &fi);
    CloseHandle(h);
    if (!ok) return GetLastError();
    if (fi.nNumberOfLinks > 1 || (fi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) return DeleteFileW(p.c_str()) ? ERROR_SUCCESS : GetLastError();
    ACL empty;
    InitializeAcl(&empty, sizeof(empty), ACL_REVISION);
    return SetNamedSecurityInfoW((LPWSTR)p.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                 NULL, NULL, &empty, NULL);
}

// Kopiuje plik, a gdy cel jest w użyciu (DLL załadowana przez Optimę, działający panel innego
// użytkownika) — odsuwa stary plik pod nazwę .old i usuwa go po restarcie. Tak działa aktualizacja.
bool Replace(const std::wstring& src, const std::wstring& dst, std::vector<std::wstring>& log) {
    if (_wcsicmp(src.c_str(), dst.c_str()) == 0) return true;
    if (CopyFileW(src.c_str(), dst.c_str(), FALSE)) { log.push_back(L"+ " + dst); return true; }
    DWORD e = GetLastError();
    if (e == ERROR_SHARING_VIOLATION || e == ERROR_ACCESS_DENIED) {
        std::wstring old = dst + L".old";
        DeleteFileW(old.c_str());
        if (MoveFileExW(dst.c_str(), old.c_str(), MOVEFILE_REPLACE_EXISTING) && CopyFileW(src.c_str(), dst.c_str(), FALSE)) {
            MoveFileExW(old.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
            log.push_back(L"+ " + dst + L" (poprzednia wersja była w użyciu — podmieniona, stara zniknie po restarcie)");
            return true;
        }
        e = GetLastError();
    }
    log.push_back(L"! " + dst + L": " + ErrorText((LONG)e));
    return false;
}

}  // namespace

void WriteInstallRegistry(HKEY root, const std::wstring& installDir, const std::wstring& exePath, const std::wstring& version, const wchar_t* role) {
    auto setS = [](HKEY h, const wchar_t* n, const std::wstring& v) { RegSetValueExW(h, n, 0, REG_SZ, (const BYTE*)v.c_str(), (DWORD)((v.size() + 1) * sizeof(wchar_t))); };
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t date[32]; swprintf_s(date, L"%04u-%02u-%02u %02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    HKEY h;
    if (RegCreateKeyExW(root, L"Software\\cp-signbridge", 0, NULL, 0, KEY_WRITE | KEY_WOW64_64KEY, NULL, &h, NULL) == ERROR_SUCCESS) {
        setS(h, L"Version", version); setS(h, L"InstallDir", installDir); setS(h, L"InstalledAt", date); setS(h, L"Role", role);
        RegCloseKey(h);
    }
    if (RegCreateKeyExW(root, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\cp-signbridge", 0, NULL, 0, KEY_WRITE | KEY_WOW64_64KEY, NULL, &h, NULL) == ERROR_SUCCESS) {
        setS(h, L"DisplayName", L"SignBridge");
        setS(h, L"DisplayVersion", version);
        setS(h, L"Publisher", L"Craftprojects Sp. z o.o.");
        setS(h, L"URLInfoAbout", L"https://craftprojects.pl");
        setS(h, L"InstallLocation", installDir);
        setS(h, L"DisplayIcon", exePath);
        setS(h, L"UninstallString", L"\"" + exePath + L"\" --uninstall");
        wchar_t d8[16]; swprintf_s(d8, L"%04u%02u%02u", st.wYear, st.wMonth, st.wDay); setS(h, L"InstallDate", d8);
        DWORD one = 1; RegSetValueExW(h, L"NoModify", 0, REG_DWORD, (const BYTE*)&one, sizeof(one)); RegSetValueExW(h, L"NoRepair", 0, REG_DWORD, (const BYTE*)&one, sizeof(one));
        RegCloseKey(h);
    }
}

void RemoveInstallRegistry(HKEY root) {
    RegDeleteKeyExW(root, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\cp-signbridge", KEY_WOW64_64KEY, 0);
    RegDeleteKeyExW(root, L"Software\\cp-signbridge", KEY_WOW64_64KEY, 0);
}

LONG RegisterCsp(const wchar_t* name, const std::wstring& imagePath, bool wow64) {
    HKEY h;
    LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, (std::wstring(kCspRegRoot) + name).c_str(), 0, NULL, 0,
                             KEY_WRITE | (wow64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), NULL, &h, NULL);
    if (r != ERROR_SUCCESS) return r;
    DWORD type = keyprov::kCspProvType;
    r = RegSetValueExW(h, L"Image Path", 0, REG_SZ, (const BYTE*)imagePath.c_str(), (DWORD)((imagePath.size() + 1) * sizeof(wchar_t)));
    if (r == ERROR_SUCCESS) r = RegSetValueExW(h, L"Type", 0, REG_DWORD, (const BYTE*)&type, sizeof(type));
    RegCloseKey(h);
    return r;
}

LONG UnregisterCsp(const wchar_t* name, bool wow64) {
    LONG r = RegDeleteKeyExW(HKEY_LOCAL_MACHINE, (std::wstring(kCspRegRoot) + name).c_str(), wow64 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY, 0);
    return r == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : r;
}

bool IsAdmin() {
    BOOL admin = FALSE;
    PSID sid = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid)) {
        CheckTokenMembership(NULL, sid, &admin);
        FreeSid(sid);
    }
    return admin == TRUE;
}

bool IsKspRegistered() {
    NCRYPT_PROV_HANDLE h = 0;
    if (NCryptOpenStorageProvider(&h, kProviderName, 0) != ERROR_SUCCESS) return false;
    NCryptFreeObject(h);
    return true;
}

std::wstring ProgramDir() { return Folder(CSIDL_PROGRAM_FILES) + L"\\cp-signbridge"; }
std::wstring ProgramDataDir() { return Folder(CSIDL_COMMON_APPDATA) + L"\\cp-signbridge"; }
std::wstring InstalledPanelVersion() { return Version(ProgramDir() + L"\\" + kAppExe); }
std::wstring PackageDir() { return ProgramDir() + L"\\pkg"; }

bool PreparePackageDir(const std::wstring& pkg, std::wstring& err) {
    std::wstring parent = pkg.substr(0, pkg.find_last_of(L'\\'));
    CreateDirectoryW(parent.c_str(), NULL);
    if (IsReparse(GetFileAttributesW(parent.c_str()))) { err = parent + L" jest dowiązaniem — przerwano."; return false; }
    RemoveDirectoryTree(pkg);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kSddlPkg, SDDL_REVISION_1, &sd, NULL)) { err = L"Prawa katalogu pakietu: " + ErrorText((LONG)GetLastError()); return false; }
    SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
    DWORD e = CreateDirectoryW(pkg.c_str(), &sa) ? ERROR_SUCCESS : GetLastError();
    LocalFree(sd);
    // plik z poprzedniej instalacji w użyciu (zniknie po restarcie) — katalog zostaje, tylko poprawiamy prawa
    if (e == ERROR_ALREADY_EXISTS) e = SetDirSecurity(pkg, kSddlPkg);
    if (e != ERROR_SUCCESS) { err = L"Nie można przygotować " + pkg + L": " + ErrorText((LONG)e); return false; }
    return true;
}

bool SecureDataDir(const std::wstring& pd, std::vector<std::wstring>& log) {
    // administrator przejmuje też obiekty założone przez zwykłych użytkowników w 1.0.0
    EnablePrivilege(SE_TAKE_OWNERSHIP_NAME);
    EnablePrivilege(SE_RESTORE_NAME);
    const std::wstring logs = pd + L"\\logs";
    for (const std::wstring* d : { &pd, &logs }) {
        DWORD a = GetFileAttributesW(d->c_str());
        if (a != INVALID_FILE_ATTRIBUTES && (IsReparse(a) || !(a & FILE_ATTRIBUTE_DIRECTORY))) { RemoveLink(*d, a); log.push_back(L"- usunięto dowiązanie " + *d); }
        CreateDirectoryW(d->c_str(), NULL);
        DWORD e = SetDirSecurity(*d, d == &pd ? kSddlData : kSddlLogs);
        if (e != ERROR_SUCCESS) { log.push_back(L"! Prawa katalogu " + *d + L": " + ErrorText((LONG)e)); return false; }
    }
    // Zawartość (np. z 1.0.0): dowiązania i katalogi poza logs\ (stary pkg\) — usunąć; pliki — prawa po katalogu
    bool ok = true;
    for (const std::wstring* d : { &pd, &logs }) {
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW((*d + L"\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            std::wstring p = *d + L"\\" + fd.cFileName;
            DWORD a = fd.dwFileAttributes;
            if (d == &pd && _wcsicmp(fd.cFileName, L"logs") == 0) continue;
            if (IsReparse(a)) { RemoveLink(p, a); log.push_back(L"- usunięto dowiązanie " + p); }
            else if (a & FILE_ATTRIBUTE_DIRECTORY) RemoveDirectoryTree(p);
            else if (DWORD e = ResetFileSecurity(p)) { log.push_back(L"! Prawa pliku " + p + L": " + ErrorText((LONG)e)); ok = false; }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    if (ok) log.push_back(L"+ Prawa " + pd + L": zapis tylko dla administratorów, każdy użytkownik widzi tylko własne logi");
    return ok;
}

bool InstallServer(const std::wstring& dir, std::vector<std::wstring>& log, bool msiMode) {
    if (!IsAdmin()) { log.push_back(L"! Wymagane uprawnienia administratora."); return false; }
    // 0. Prawa katalogu danych przed czymkolwiek innym (naprawia też instalację 1.0.0)
    std::wstring pd = ProgramDataDir();
    if (!SecureDataDir(pd, log)) return false;
    std::wstring src64 = dir + L"\\x64\\" + kDllName;
    std::wstring src86 = dir + L"\\x86\\" + kDllName;
    if (!FileExists(src64)) src64 = dir + L"\\" + kDllName;
    if (!FileExists(src64)) { log.push_back(L"! Brak " + src64); return false; }

    // 1. DLL dostawcy do katalogów systemowych
    std::wstring dst64 = SysDir(false) + L"\\" + kDllName;
    std::wstring dst86 = SysDir(true) + L"\\" + kDllName;
    if (!Replace(src64, dst64, log)) return false;
    if (FileExists(src86)) { if (!Replace(src86, dst86, log)) return false; }
    else log.push_back(L"~ Brak wersji x86 — programy 32-bitowe nie zobaczą dostawcy.");
    // 1b. DLL dostawcy CAPI (tryb zgodności ze starszymi programami) — obok KSP
    std::wstring csp64 = dir + L"\\x64\\" + kCspDllName;
    std::wstring csp86 = dir + L"\\x86\\" + kCspDllName;
    if (!FileExists(csp64)) csp64 = dir + L"\\" + kCspDllName;
    std::wstring dstCsp64 = SysDir(false) + L"\\" + kCspDllName;
    std::wstring dstCsp86 = SysDir(true) + L"\\" + kCspDllName;
    bool haveCsp = FileExists(csp64), haveCsp86 = haveCsp && FileExists(csp86);
    if (haveCsp) {
        if (!Replace(csp64, dstCsp64, log)) return false;
        if (haveCsp86) { if (!Replace(csp86, dstCsp86, log)) return false; }
        else log.push_back(L"~ Brak wersji x86 dostawcy CAPI — starsze programy 32-bitowe go nie zobaczą.");
    } else log.push_back(std::wstring(L"~ Brak ") + kCspDllName + L" w pakiecie — bez trybu zgodności ze starszymi programami (CAPI).");

    // 2. Program (panel + sbctl) do Program Files
    std::wstring pf = ProgramDir();
    CreateDirectoryW(pf.c_str(), NULL);
    CreateDirectoryW((pf + L"\\x64").c_str(), NULL);
    CreateDirectoryW((pf + L"\\x86").c_str(), NULL);
    bool haveApp = FileExists(dir + L"\\" + kAppExe) || (msiMode && FileExists(pf + L"\\" + kAppExe));
    if (msiMode) log.push_back(L"+ Program zainstalowany przez pakiet MSI: " + pf + L"\\" + kAppExe);
    else if (haveApp) { if (!Replace(dir + L"\\" + kAppExe, pf + L"\\" + kAppExe, log)) return false; }
    else log.push_back(std::wstring(L"~ Brak ") + kAppExe + L" w pakiecie (instalacja z sbctl) — bez panelu i autostartu.");
    if (FileExists(dir + L"\\sbctl.exe")) Replace(dir + L"\\sbctl.exe", pf + L"\\sbctl.exe", log);
    // kopie DLL w Program Files (źródło do ponownej instalacji / podglądu wersji)
    Replace(src64, pf + L"\\x64\\" + kDllName, log);
    if (FileExists(src86)) Replace(src86, pf + L"\\x86\\" + kDllName, log);

    // 3. Logi (katalog i prawa przygotował krok 0)
    log.push_back(L"+ Logi: " + pd + L"\\logs");

    // 4. Rejestracja dostawcy w CNG
    PWSTR fns[] = { (PWSTR)NCRYPT_KEY_STORAGE_ALGORITHM };
    CRYPT_INTERFACE_REG iface = {};
    iface.dwInterface = NCRYPT_KEY_STORAGE_INTERFACE;
    iface.dwFlags = CRYPT_LOCAL;
    iface.cFunctions = 1;
    iface.rgpszFunctions = fns;
    PCRYPT_INTERFACE_REG ifaces[] = { &iface };
    CRYPT_IMAGE_REG img = {};
    img.pszImage = (PWSTR)dst64.c_str();  // procesy 32-bit: WOW64 przekieruje System32 -> SysWOW64
    img.cInterfaces = 1;
    img.rgpInterfaces = ifaces;
    CRYPT_PROVIDER_REG reg = {};
    reg.pUM = &img;
    BCryptReg api;
    if (!api.Load()) { log.push_back(L"! Brak funkcji rejestracji dostawcy w bcrypt.dll"); return false; }
    NTSTATUS st = api.Register(kProviderName, 0, &reg);
    if (!BCRYPT_SUCCESS(st) && st != (NTSTATUS)0xC0000035 /*STATUS_OBJECT_NAME_COLLISION*/) {
        log.push_back(L"! BCryptRegisterProvider: " + ErrorText(st)); return false;
    }
    st = api.AddCtx(CRYPT_LOCAL, NULL, NCRYPT_KEY_STORAGE_INTERFACE, NCRYPT_KEY_STORAGE_ALGORITHM, kProviderName, CRYPT_PRIORITY_BOTTOM);
    if (!BCRYPT_SUCCESS(st) && st != (NTSTATUS)0xC0000035) {
        log.push_back(L"! BCryptAddContextFunctionProvider: " + ErrorText(st)); return false;
    }
    log.push_back(std::wstring(L"+ Zarejestrowano dostawcę: ") + kProviderName);

    // 4b. Rejestracja dostawcy CAPI: osobno dla programów 64-bitowych i 32-bitowych (WOW6432Node)
    if (haveCsp) {
        LONG e = RegisterCsp(keyprov::kCspName, dstCsp64, false);
        if (e == ERROR_SUCCESS && haveCsp86) e = RegisterCsp(keyprov::kCspName, dstCsp86, true);
        if (e != ERROR_SUCCESS) { log.push_back(L"! Rejestracja dostawcy CAPI: " + ErrorText(e)); return false; }
        log.push_back(std::wstring(L"+ Zarejestrowano dostawcę CAPI: ") + keyprov::kCspName + (haveCsp86 ? L" (x64 i x86)" : L" (x64)"));
    }

    // 5. Panel startuje przy logowaniu każdego użytkownika (w sesji RDP sam pobiera certyfikaty)
    std::wstring cmd = L"\"" + pf + L"\\" + kAppExe + L"\" --tray";
    HKEY h;
    if (!haveApp) {}
    else if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRunKey, 0, NULL, 0, KEY_WRITE | KEY_WOW64_64KEY, NULL, &h, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(h, kRunValue, 0, REG_SZ, (const BYTE*)cmd.c_str(), (DWORD)((cmd.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(h);
        log.push_back(L"+ Panel uruchamia się przy logowaniu każdego użytkownika.");
    } else log.push_back(L"~ Nie udało się ustawić autostartu panelu (HKLM Run).");

    if (haveApp && !msiMode) WriteInstallRegistry(HKEY_LOCAL_MACHINE, pf, pf + L"\\" + kAppExe, Version(pf + L"\\" + kAppExe), L"server");
    if (!IsKspRegistered()) { log.push_back(L"! Test otwarcia dostawcy nie powiódł się."); return false; }
    log.push_back(L"+ Test otwarcia dostawcy: OK. Wersja: " + Version(pf + L"\\" + kAppExe));
    // dostawca CAPI jest dodatkiem: gdy Windows go nie ładuje, certyfikaty zostają przy dostawcy CNG (keyprov::Effective)
    if (haveCsp) log.push_back(keyprov::IsCspRegistered() ? L"+ Test otwarcia dostawcy CAPI: OK."
                                                          : L"~ Test otwarcia dostawcy CAPI nie powiódł się — tryb zgodności niedostępny, certyfikaty zostają przy dostawcy CNG.");
    return true;
}

bool UninstallServer(std::vector<std::wstring>& log, bool msiMode) {
    if (!IsAdmin()) { log.push_back(L"! Wymagane uprawnienia administratora."); return false; }
    BCryptReg api;
    if (!api.Load()) { log.push_back(L"! Brak funkcji rejestracji dostawcy w bcrypt.dll"); return false; }
    NTSTATUS st = api.RemoveCtx(CRYPT_LOCAL, NULL, NCRYPT_KEY_STORAGE_INTERFACE, NCRYPT_KEY_STORAGE_ALGORITHM, kProviderName);
    log.push_back(L". RemoveContextFunctionProvider: " + ErrorText(st));
    st = api.Unregister(kProviderName);
    log.push_back(L". UnregisterProvider: " + ErrorText(st));
    for (bool w : { false, true }) {
        LONG e = UnregisterCsp(keyprov::kCspName, w);
        if (e != ERROR_SUCCESS) log.push_back(std::wstring(L"~ Wyrejestrowanie dostawcy CAPI") + (w ? L" (x86): " : L" (x64): ") + ErrorText(e));
    }
    for (const wchar_t* dll : { kDllName, kCspDllName }) for (bool w : { false, true }) {
        std::wstring p = SysDir(w) + L"\\" + dll;
        if (!FileExists(p)) continue;
        if (DeleteFileW(p.c_str())) log.push_back(L"- " + p);
        else { MoveFileExW(p.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT); log.push_back(L"~ " + p + L" w użyciu — zniknie po restarcie"); }
    }
    HKEY h;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRunKey, 0, KEY_WRITE | KEY_WOW64_64KEY, &h) == ERROR_SUCCESS) {
        RegDeleteValueW(h, kRunValue);
        RegCloseKey(h);
    }
    RemoveAllUsersConfig();
    RemoveDirectoryTree(ProgramDataDir());
    RemoveDirectoryTree(PackageDir());
    log.push_back(L"+ Usunięto logi, konfigurację użytkowników i wpisy rejestru.");
    if (msiMode) { log.push_back(L"+ Dostawca wyrejestrowany; pliki programu usuwa pakiet MSI."); return true; }
    RemoveInstallRegistry(HKEY_LOCAL_MACHINE);
    RemoveDirectoryTree(ProgramDir());   // uruchomiony program zniknie po restarcie
    log.push_back(L"+ Odinstalowano. Jeśli jakiś plik był w użyciu, zniknie po restarcie.");
    return true;
}

void RemoveDirectoryTree(const std::wstring& dir) {
    DWORD top = GetFileAttributesW(dir.c_str());
    if (top == INVALID_FILE_ATTRIBUTES) return;
    if (IsReparse(top)) { RemoveLink(dir, top); return; }
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring p = dir + L"\\" + fd.cFileName;
        // junction / symlink: tylko samo dowiązanie (wejście do środka kasowałoby cudze pliki jako SYSTEM)
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) RemoveLink(p, fd.dwFileAttributes);
        else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) RemoveDirectoryTree(p);
        else { SetFileAttributesW(p.c_str(), FILE_ATTRIBUTE_NORMAL); if (!DeleteFileW(p.c_str())) MoveFileExW(p.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT); }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    if (!RemoveDirectoryW(dir.c_str())) MoveFileExW(dir.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
}

void RemoveCurrentUserConfig() {
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\cp-signbridge");
    RegDeleteKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\cp-signbridge", KEY_WOW64_64KEY, 0);
}

void RemoveAllUsersConfig() {
    RemoveCurrentUserConfig();
    HKEY users;
    if (RegOpenKeyExW(HKEY_USERS, NULL, 0, KEY_READ, &users) != ERROR_SUCCESS) return;
    for (DWORD i = 0;; ++i) {
        wchar_t name[256]; DWORD cb = 256;
        if (RegEnumKeyExW(users, i, name, &cb, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        HKEY u;
        if (RegOpenKeyExW(HKEY_USERS, name, 0, KEY_READ | KEY_WRITE, &u) != ERROR_SUCCESS) continue;
        RegDeleteTreeW(u, L"Software\\cp-signbridge");
        RegDeleteKeyExW(u, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\cp-signbridge", KEY_WOW64_64KEY, 0);
        HKEY run;
        if (RegOpenKeyExW(u, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &run) == ERROR_SUCCESS) { RegDeleteValueW(run, L"cp-signbridge-panel"); RegCloseKey(run); }
        RegCloseKey(u);
    }
    RegCloseKey(users);
}

}}  // namespace sb::kspsetup

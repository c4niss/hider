#include <Windows.h>
#include <iostream>
#include <fstream>
#include <sstream>

// Fonction utilitaire pour convertir int en string
std::string IntToString(int value) {
    std::stringstream ss;
    ss << value;
    return ss.str();
}

void WriteToLog(const std::string& message) {
    std::ofstream logfile("process_child_log.txt", std::ios_base::app);
    if (logfile.is_open()) {
        logfile << message << std::endl;
        logfile.close();
    }
}

int main() {
    AllocConsole();

    // Rediriger stdout et stderr vers la console
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hStderr = GetStdHandle(STD_ERROR_HANDLE);
    if (hStdout != INVALID_HANDLE_VALUE && hStderr != INVALID_HANDLE_VALUE) {
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
    }

    // Écrire dans un fichier log pour confirmer l'existence
    WriteToLog("=== PROCESS_CHILD.EXE DÉMARRÉ ===");
    WriteToLog("PID: " + IntToString(GetCurrentProcessId()));

    std::cout << "=== PROCESSUS ENFANT process_child.exe ===" << std::endl;
    std::cout << "PID: " << GetCurrentProcessId() << std::endl;
    std::cout << "Vérifiez le fichier 'process_child_log.txt' pour confirmer l'exécution!" << std::endl;
    std::cout << "Ce processus s'executera pendant 5 minutes." << std::endl;

    for (int i = 0; i < 300; i++) {
        if (i % 30 == 0) {
            std::string logMsg = "process_child.exe actif depuis " + IntToString(i) +
                " secondes. PID: " + IntToString(GetCurrentProcessId());
            std::cout << logMsg << std::endl;
            WriteToLog(logMsg);

            // Créer aussi un fichier témoin à intervalle régulier
            std::ofstream witness(("process_child_witness_" + IntToString(i) + ".txt").c_str());
            if (witness.is_open()) {
                witness << "Témoin créé à " << i << " secondes - PID: " << GetCurrentProcessId() << std::endl;
                witness.close();
            }
        }
        Sleep(1000);
    }

    WriteToLog("=== PROCESS_CHILD.EXE TERMINÉ ===");
    std::cout << "=== PROCESS_CHILD.EXE TERMINE ===" << std::endl;

    // Créer un fichier final
    std::ofstream final("process_child_final.txt");
    if (final.is_open()) {
        final << "Processus terminé normalement après 5 minutes" << std::endl;
        final.close();
    }

    FreeConsole();
    return 0;
}
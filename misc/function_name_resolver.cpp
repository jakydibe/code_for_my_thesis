#include <windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

// Funzione per calcolare l'hash SHA-256 di una stringa
std::string sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Funzione per trovare il nome della funzione data una DLL e un hash
std::string resolveFunctionName(HMODULE module, const std::string& targetHash) {
    // Puntatore alla tabella degli indirizzi delle esportazioni
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)module + dosHeader->e_lfanew);
    auto exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        (BYTE*)module + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    // Array di nomi delle funzioni
    auto names = reinterpret_cast<DWORD*>((BYTE*)module + exportDirectory->AddressOfNames);
    
    for (size_t i = 0; i < exportDirectory->NumberOfNames; i++) {
        std::string functionName = (char*)module + names[i];
        std::string hash = sha256(functionName);
        
        if (hash == targetHash) {
            return functionName;
        }
    }
    
    return "";
}

int main() {
    const char* dllName = "dll.dll";
    std::string functionHash = "HASH_DEL_NOME_DELLA_FUNZIONE";  // Inserisci l'hash della funzione qui

    HMODULE hModule = GetModuleHandleA(dllName);
    if (hModule == NULL) {
        std::cerr << "Errore nel caricamento del modulo." << std::endl;
        return 1;
    }

    std::string functionName = resolveFunctionName(hModule, functionHash);
    if (functionName.empty()) {
        std::cerr << "Funzione non trovata." << std::endl;
        return 1;
    }

    FARPROC procAddress = GetProcAddress(hModule, functionName.c_str());
    if (procAddress == NULL) {
        std::cerr << "Errore nel recupero dell'indirizzo della funzione." << std::endl;
        return 1;
    }

    std::cout << "Indirizzo della funzione: " << procAddress << std::endl;

    return 0;
}

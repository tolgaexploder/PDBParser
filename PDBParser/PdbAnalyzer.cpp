#include "PdbAnalyzer.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <filesystem>

PdbAnalyzer::PdbAnalyzer(const std::wstring& pdbPath) {
    try {
        m_parser = std::make_unique<PdbParser>(pdbPath);
        if (!m_parser->IsInitialized()) {
            throw std::runtime_error("Failed to initialize PDB parser");
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        throw;
    }
}

void PdbAnalyzer::PrintHeader(const std::string& title) const {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  " << title << "\n";
    std::cout << std::string(60, '=') << "\n";
}

void PdbAnalyzer::PrintSymbolInfo(const SymbolInfo& symbol) const {
    std::cout << std::hex << "0x" << std::setw(8) << std::setfill('0') << symbol.rva
        << " | " << std::setw(8) << symbol.size
        << " | " << symbol.name << "\n";
}

void PdbAnalyzer::PrintStructInfo(const StructInfo& structInfo) const {
    std::cout << "Structure: " << structInfo.name << " (Size: "
        << structInfo.size << " bytes)\n";
    std::cout << "Members:\n";

    for (const auto& member : structInfo.members) {
        std::cout << "  +0x" << std::hex << std::setw(4) << std::setfill('0')
            << member.offset << " | " << std::setw(8) << member.size
            << " | " << member.name << "\n";
    }
}

void PdbAnalyzer::ShowBasicInfo() const {
    PrintHeader("PDB Basic Information");

    std::wcout << L"PDB Path: " << m_parser->GetPdbPath() << L"\n";
    std::cout << "Machine Type: ";

    switch (m_parser->GetMachineType()) {
    case MachineType::x86: std::cout << "x86 (32-bit)\n"; break;
    case MachineType::x64: std::cout << "x64 (64-bit)\n"; break;
    case MachineType::ARM: std::cout << "ARM\n"; break;
    case MachineType::ARM64: std::cout << "ARM64\n"; break;
    case MachineType::IA64: std::cout << "IA64\n"; break;
    default: std::cout << "Unknown\n"; break;
    }
}

void PdbAnalyzer::AnalyzeSymbols(size_t maxResults) const {
    PrintHeader("Symbol Analysis");

    auto start = std::chrono::high_resolution_clock::now();
    auto symbols = m_parser->GetAllPublicSymbols();
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Found " << symbols.size() << " symbols in "
        << duration.count() << "ms\n\n";

    std::cout << std::hex << "RVA      | Size     | Symbol Name\n";
    std::cout << std::string(60, '-') << "\n";

    size_t count = 0;
    for (const auto& symbol : symbols) {
        if (count++ >= maxResults) {
            std::cout << "... and " << (symbols.size() - maxResults) << " more\n";
            break;
        }
        PrintSymbolInfo(symbol);
    }
}

void PdbAnalyzer::FindSpecificSymbol(const std::wstring& symbolName) const {
    PrintHeader("Symbol Lookup");

    auto start = std::chrono::high_resolution_clock::now();
    auto rva = m_parser->GetSymbolRva(symbolName);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    std::wcout << L"Searching for: " << symbolName << L"\n";
    std::cout << "Lookup time: " << duration.count() << "μs\n";

    if (rva) {
        std::cout << "Found at RVA: 0x" << std::hex << *rva << "\n";
    }
    else {
        std::cout << "Symbol not found\n";
    }
}

void PdbAnalyzer::AnalyzeStructure(const std::wstring& structName) const {
    PrintHeader("Structure Analysis");

    auto structInfo = m_parser->GetStructInfo(structName);
    if (structInfo) {
        PrintStructInfo(*structInfo);
    }
    else {
        std::wcout << L"Structure '" << structName << L"' not found\n";
    }
}

void PdbAnalyzer::FindStructMember(const std::wstring& structName, const std::wstring& memberName) const {
    PrintHeader("Structure Member Lookup");

    auto offset = m_parser->GetStructMemberOffset(structName, memberName);

    std::wcout << L"Struct: " << structName << L", Member: " << memberName << L"\n";

    if (offset) {
        std::cout << "Member offset: +0x" << std::hex << *offset << "\n";
    }
    else {
        std::cout << "Member not found\n";
    }
}

void PdbAnalyzer::SearchByPattern(const std::wstring& pattern, size_t maxResults) const {
    PrintHeader("Pattern Search");

    std::wcout << L"Pattern: " << pattern << L"\n";

    auto start = std::chrono::high_resolution_clock::now();
    auto matches = m_parser->FindSymbolsByPattern(pattern);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Found " << matches.size() << " matches in "
        << duration.count() << "ms\n\n";

    std::cout << std::hex << "RVA      | Size     | Symbol Name\n";
    std::cout << std::string(60, '-') << "\n";

    size_t count = 0;
    for (const auto& match : matches) {
        if (count++ >= maxResults) {
            std::cout << "... and " << (matches.size() - maxResults) << " more\n";
            break;
        }
        PrintSymbolInfo(match);
    }
}

void PdbAnalyzer::PerformanceTest() const {
    PrintHeader("Performance Test");

    auto start = std::chrono::high_resolution_clock::now();
    auto symbols = m_parser->GetAllPublicSymbols();
    auto end = std::chrono::high_resolution_clock::now();
    auto coldTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "Cold symbol enumeration: " << coldTime.count() << "ms\n";

    start = std::chrono::high_resolution_clock::now();
    m_parser->PreloadSymbols();
    end = std::chrono::high_resolution_clock::now();
    auto preloadTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "Symbol preload time: " << preloadTime.count() << "ms\n";

    if (!symbols.empty()) {
        std::wstring testSymbol(symbols[symbols.size() / 2].name.begin(),
            symbols[symbols.size() / 2].name.end());

        start = std::chrono::high_resolution_clock::now();
        auto rva = m_parser->GetSymbolRva(testSymbol);
        end = std::chrono::high_resolution_clock::now();
        auto hotTime = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        std::cout << "Hot symbol lookup: " << hotTime.count() << "μs\n";
        std::cout << "Speedup factor: " << (coldTime.count() * 1000.0) / hotTime.count() << "x\n";
    }
}

void PdbAnalyzer::ListStructures(size_t maxResults) const {
    PrintHeader("Available Structures");

    auto structNames = m_parser->GetAllStructNames();
    std::cout << "Found " << structNames.size() << " structures\n\n";

    size_t count = 0;
    for (const auto& name : structNames) {
        if (count++ >= maxResults) {
            std::cout << "... and " << (structNames.size() - maxResults) << " more\n";
            break;
        }
        std::wcout << name << L"\n";
    }
}

void PdbAnalyzer::ExportResults(const std::wstring& outputPath) const {
    PrintHeader("Export Results");

    std::wcout << L"Exporting to: " << outputPath << L"\n";

    if (m_parser->DumpToJson(outputPath)) {
        std::cout << "Export successful\n";
    }
    else {
        std::cout << "Export failed\n";
    }
}

#include <wininet.h>
#pragma comment(lib, "wininet.lib")

std::string PdbDownloader::ExtractPdbInfo(const std::wstring& exePath) {
    HANDLE hFile = CreateFileW(exePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return "";

    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) { CloseHandle(hFile); return ""; }

    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) { CloseHandle(hMapping); CloseHandle(hFile); return ""; }

    std::string result;

    IMAGE_DOS_HEADER* dosHeader = nullptr;
    IMAGE_NT_HEADERS* ntHeaders = nullptr;
    IMAGE_DATA_DIRECTORY* debugDir = nullptr;
    IMAGE_DEBUG_DIRECTORY* debugInfo = nullptr;

    dosHeader = (IMAGE_DOS_HEADER*)pBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) goto cleanup;

    ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)pBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) goto cleanup;

    debugDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (debugDir->VirtualAddress == 0) goto cleanup;

    debugInfo = (IMAGE_DEBUG_DIRECTORY*)((BYTE*)pBase + debugDir->VirtualAddress);

    for (DWORD i = 0; i < debugDir->Size / sizeof(IMAGE_DEBUG_DIRECTORY); i++) {
        if (debugInfo[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
            BYTE* cvData = (BYTE*)pBase + debugInfo[i].AddressOfRawData;

            if (*(DWORD*)cvData == 0x53445352) { // 'RSDS'
                GUID* guid = (GUID*)(cvData + 4);
                DWORD age = *(DWORD*)(cvData + 20);
                char* pdbName = (char*)(cvData + 24);

                char guidStr[64];
                sprintf_s(guidStr, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
                    guid->Data1, guid->Data2, guid->Data3,
                    guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
                    guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7], age);

                result = std::string(pdbName) + "|" + guidStr;
                break;
            }
        }
    }

cleanup:
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return result;
}

bool PdbDownloader::DownloadFile(const std::string& url, const std::wstring& outputPath) {
    HINTERNET hInternet = InternetOpenA("PdbParser/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hInternet) return false;

    HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), nullptr, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return false;
    }

    HANDLE hFile = CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return false;
    }

    char buffer[8192];
    DWORD bytesRead, bytesWritten;
    bool success = true;

    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        if (!WriteFile(hFile, buffer, bytesRead, &bytesWritten, nullptr) || bytesWritten != bytesRead) {
            success = false;
            break;
        }
    }

    CloseHandle(hFile);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    if (!success) {
        DeleteFileW(outputPath.c_str());
    }

    return success;
}

std::optional<std::wstring> PdbDownloader::DownloadPdbForExecutable(const std::wstring& exePath) {
    std::string pdbInfo = ExtractPdbInfo(exePath);
    if (pdbInfo.empty()) return std::nullopt;

    size_t pos = pdbInfo.find('|');
    if (pos == std::string::npos) return std::nullopt;

    std::string pdbName = pdbInfo.substr(0, pos);
    std::string guidAge = pdbInfo.substr(pos + 1);

    std::wstring symbolDir = L"C:\\Symbols\\";
    CreateDirectoryW(symbolDir.c_str(), nullptr);

    std::wstring pdbDir = symbolDir + std::wstring(pdbName.begin(), pdbName.end()) + L"\\";
    CreateDirectoryW(pdbDir.c_str(), nullptr);

    std::wstring guidDir = pdbDir + std::wstring(guidAge.begin(), guidAge.end()) + L"\\";
    CreateDirectoryW(guidDir.c_str(), nullptr);

    std::wstring pdbPath = guidDir + std::wstring(pdbName.begin(), pdbName.end());

    if (std::filesystem::exists(pdbPath)) {
        return pdbPath;
    }

    // Download from Microsoft Symbol Server
    std::string url = "https://msdl.microsoft.com/download/symbols/" +
        pdbName + "/" + guidAge + "/" + pdbName;

    std::wcout << L"Downloading PDB from: " << std::wstring(url.begin(), url.end()) << L"\n";
    std::wcout << L"Saving to: " << pdbPath << L"\n";

    if (DownloadFile(url, pdbPath)) {
        return pdbPath;
    }

    return std::nullopt;
}
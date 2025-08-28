#include "PdbParser.h"
#include <algorithm>
#include <regex>
#include <fstream>
#include <cvconst.h>
#include <filesystem>
#include <iostream>

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return {};

    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};

    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
    return result;
}

PdbParser::PdbParser(const std::wstring& pdbPath)
    : m_pdbPath(pdbPath), m_machineType(MachineType::x86) {

    if (FAILED(CoInitialize(nullptr))) {
        throw std::runtime_error("Failed to initialize COM");
    }

    if (!InitializeDia()) {
        CleanupCom();
        throw std::runtime_error("Failed to initialize DIA SDK");
    }
}

bool PdbParser::InitializeDia() noexcept {
    HRESULT hr = CoCreateInstance(__uuidof(DiaSource), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(IDiaDataSource), reinterpret_cast<void**>(&m_pDataSource));

    if (FAILED(hr)) {
        system("regsvr32 /s msdia140.dll");
        hr = CoCreateInstance(__uuidof(DiaSource), nullptr, CLSCTX_INPROC_SERVER,
            __uuidof(IDiaDataSource), reinterpret_cast<void**>(&m_pDataSource));
        if (FAILED(hr)) return false;
    }

    hr = m_pDataSource->loadDataFromPdb(m_pdbPath.c_str());
    if (FAILED(hr)) return false;

    hr = m_pDataSource->openSession(&m_pSession);
    if (FAILED(hr)) return false;

    hr = m_pSession->get_globalScope(&m_pGlobalScope);
    if (FAILED(hr)) return false;

    DWORD machType = 0;
    if (SUCCEEDED(m_pGlobalScope->get_machineType(&machType))) {
        m_machineType = static_cast<MachineType>(machType);
    }

    return true;
}

void PdbParser::CleanupCom() noexcept {
    CoUninitialize();
}

template<typename Func>
bool PdbParser::EnumerateSymbols(enum SymTagEnum symTag, const Func& callback) const {
    CComPtr<IDiaEnumSymbols> pEnumSymbols;
    if (FAILED(m_pGlobalScope->findChildren(symTag, nullptr, nsNone, &pEnumSymbols))) {
        return false;
    }

    CComPtr<IDiaSymbol> pSymbol;
    ULONG celt = 0;

    while (SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && celt == 1) {
        try {
            if (!callback(pSymbol)) break;
        }
        catch (...) {
        }
        pSymbol.Release();
    }

    return true;
}

std::vector<SymbolInfo> PdbParser::GetAllPublicSymbols() const {
    std::vector<SymbolInfo> symbols;
    symbols.reserve(2000);

    EnumerateSymbols(SymTagPublicSymbol, [&](CComPtr<IDiaSymbol>& pSymbol) -> bool {
        try {
            CComBSTR bstrName;
            DWORD rva = 0;
            ULONGLONG length = 0;
            DWORD typeId = 0;

            if (SUCCEEDED(pSymbol->get_undecoratedNameEx(0x1000, &bstrName)) &&
                bstrName && bstrName.Length() > 0 &&
                SUCCEEDED(pSymbol->get_relativeVirtualAddress(&rva)) &&
                SUCCEEDED(pSymbol->get_length(&length)) &&
                SUCCEEDED(pSymbol->get_typeId(&typeId))) {

                std::wstring wname(bstrName.m_str, bstrName.Length());
                std::string safeName = WStringToString(wname);

                if (!safeName.empty()) {
                    symbols.emplace_back(SymbolInfo{
                        std::move(safeName),
                        static_cast<DWORD64>(rva),
                        static_cast<DWORD64>(length),
                        typeId
                        });
                }
            }
        }
        catch (...) {
        }

        return symbols.size() < 5000;
        });

    std::sort(symbols.begin(), symbols.end(),
        [](const SymbolInfo& a, const SymbolInfo& b) { return a.rva < b.rva; });

    return symbols;
}

std::optional<DWORD64> PdbParser::GetSymbolRva(const std::wstring& symbolName) const {
    auto it = m_symbolCache.find(symbolName);
    if (it != m_symbolCache.end()) {
        return it->second;
    }

    DWORD64 rva = 0;
    bool found = false;

    EnumerateSymbols(SymTagPublicSymbol, [&](CComPtr<IDiaSymbol>& pSymbol) -> bool {
        try {
            CComBSTR bstrName;
            if (SUCCEEDED(pSymbol->get_undecoratedNameEx(0x1000, &bstrName)) &&
                bstrName && bstrName.Length() > 0) {

                if (wcscmp(symbolName.c_str(), bstrName.m_str) == 0) {
                    DWORD tempRva = 0;
                    if (SUCCEEDED(pSymbol->get_relativeVirtualAddress(&tempRva))) {
                        rva = static_cast<DWORD64>(tempRva);
                        found = true;
                        return false;
                    }
                }
            }
        }
        catch (...) {
        }
        return true;
        });

    if (found) {
        m_symbolCache[symbolName] = rva;
        return rva;
    }

    return std::nullopt;
}

std::vector<SymbolInfo> PdbParser::FindSymbolsByPattern(const std::wstring& pattern) const {
    std::vector<SymbolInfo> matches;
    matches.reserve(100);

    try {
        std::wregex regex(pattern, std::regex_constants::icase);

        EnumerateSymbols(SymTagPublicSymbol, [&](CComPtr<IDiaSymbol>& pSymbol) -> bool {
            try {
                CComBSTR bstrName;
                if (SUCCEEDED(pSymbol->get_undecoratedNameEx(0x1000, &bstrName)) &&
                    bstrName && bstrName.Length() > 0) {

                    std::wstring name(bstrName.m_str, bstrName.Length());
                    if (std::regex_search(name, regex)) {
                        DWORD rva = 0;
                        ULONGLONG length = 0;
                        DWORD typeId = 0;

                        if (SUCCEEDED(pSymbol->get_relativeVirtualAddress(&rva)) &&
                            SUCCEEDED(pSymbol->get_length(&length)) &&
                            SUCCEEDED(pSymbol->get_typeId(&typeId))) {

                            std::string safeName = WStringToString(name);
                            if (!safeName.empty()) {
                                matches.emplace_back(SymbolInfo{
                                    std::move(safeName),
                                    static_cast<DWORD64>(rva),
                                    static_cast<DWORD64>(length),
                                    typeId
                                    });
                            }
                        }
                    }
                }
            }
            catch (...) {
            }

            return matches.size() < 200; // Limit
            });

    }
    catch (const std::regex_error&) {
    }

    return matches;
}

std::optional<StructInfo> PdbParser::GetStructInfo(const std::wstring& structName) const {
    auto it = m_structCache.find(structName);
    if (it != m_structCache.end()) {
        return it->second;
    }

    return ParseStructInternal(structName);
}

std::optional<StructInfo> PdbParser::ParseStructInternal(const std::wstring& structName) const {
    StructInfo structInfo;
    bool found = false;

    EnumerateSymbols(SymTagUDT, [&](CComPtr<IDiaSymbol>& pSymbol) -> bool {
        try {
            CComBSTR bstrName;
            if (SUCCEEDED(pSymbol->get_name(&bstrName)) &&
                bstrName && bstrName.Length() > 0) {

                if (wcscmp(structName.c_str(), bstrName.m_str) == 0) {
                    std::wstring wStructName(bstrName.m_str, bstrName.Length());
                    structInfo.name = WStringToString(wStructName);

                    ULONGLONG structSize = 0;
                    if (SUCCEEDED(pSymbol->get_length(&structSize))) {
                        structInfo.size = static_cast<DWORD64>(structSize);
                    }

                    CComPtr<IDiaEnumSymbols> pEnumMembers;
                    if (SUCCEEDED(pSymbol->findChildren(SymTagData, nullptr, nsNone, &pEnumMembers))) {
                        CComPtr<IDiaSymbol> pMember;
                        ULONG celt = 0;

                        while (SUCCEEDED(pEnumMembers->Next(1, &pMember, &celt)) &&
                            celt == 1 && structInfo.members.size() < 100) {

                            try {
                                CComBSTR memberName;
                                LONG offset = 0;
                                ULONGLONG memberSize = 0;
                                DWORD typeId = 0;

                                if (SUCCEEDED(pMember->get_name(&memberName)) &&
                                    memberName && memberName.Length() > 0 &&
                                    SUCCEEDED(pMember->get_offset(&offset)) &&
                                    SUCCEEDED(pMember->get_length(&memberSize)) &&
                                    SUCCEEDED(pMember->get_typeId(&typeId))) {

                                    std::wstring wMemberName(memberName.m_str, memberName.Length());
                                    std::string safeMemberName = WStringToString(wMemberName);

                                    if (!safeMemberName.empty()) {
                                        structInfo.members.emplace_back(StructMember{
                                            std::move(safeMemberName),
                                            static_cast<DWORD64>(offset >= 0 ? offset : 0),
                                            static_cast<DWORD64>(memberSize),
                                            typeId
                                            });
                                    }
                                }
                            }
                            catch (...) {
                            }

                            pMember.Release();
                        }
                    }

                    found = true;
                    return false;
                }
            }
        }
        catch (...) {
        }
        return true;
        });

    if (found) {
        std::sort(structInfo.members.begin(), structInfo.members.end(),
            [](const StructMember& a, const StructMember& b) { return a.offset < b.offset; });

        m_structCache[structName] = structInfo;
        return structInfo;
    }

    return std::nullopt;
}

std::optional<DWORD64> PdbParser::GetStructMemberOffset(const std::wstring& structName,
    const std::wstring& memberName) const {
    auto structInfo = GetStructInfo(structName);
    if (!structInfo) return std::nullopt;

    std::string memberNameStr = WStringToString(memberName);
    auto it = std::find_if(structInfo->members.begin(), structInfo->members.end(),
        [&](const StructMember& member) { return member.name == memberNameStr; });

    return (it != structInfo->members.end()) ? std::optional<DWORD64>(it->offset) : std::nullopt;
}

void PdbParser::PreloadSymbols() {
    auto symbols = GetAllPublicSymbols();
    for (const auto& symbol : symbols) {
        std::wstring wname = std::wstring(symbol.name.begin(), symbol.name.end());
        m_symbolCache[wname] = symbol.rva;
    }
}

void PdbParser::PreloadStructures() {
    std::vector<std::wstring> structNames = GetAllStructNames();
    for (const auto& name : structNames) {
        ParseStructInternal(name);
    }
}

void PdbParser::ClearCaches() noexcept {
    m_symbolCache.clear();
    m_structCache.clear();
}

std::vector<std::wstring> PdbParser::GetAllStructNames() const {
    std::vector<std::wstring> names;
    names.reserve(500);

    EnumerateSymbols(SymTagUDT, [&](CComPtr<IDiaSymbol>& pSymbol) -> bool {
        try {
            CComBSTR bstrName;
            if (SUCCEEDED(pSymbol->get_name(&bstrName)) &&
                bstrName && bstrName.Length() > 0) {
                names.emplace_back(std::wstring(bstrName.m_str, bstrName.Length()));
            }
        }
        catch (...) {
        }

        return names.size() < 1000; // Limit
        });

    return names;
}

bool PdbParser::DumpToJson(const std::wstring& outputPath) const {
    try {
        std::wofstream file(outputPath);
        if (!file.is_open()) return false;

        file << L"{\n";
        file << L"  \"pdb_info\": {\n";
        file << L"    \"path\": \"" << m_pdbPath << L"\",\n";
        file << L"    \"machine_type\": " << static_cast<DWORD>(m_machineType) << L"\n";
        file << L"  },\n";

        auto symbols = GetAllPublicSymbols();
        file << L"  \"symbols\": [\n";

        for (size_t i = 0; i < symbols.size(); ++i) {
            const auto& symbol = symbols[i];
            std::wstring wname = std::wstring(symbol.name.begin(), symbol.name.end());

            std::wstring escaped_name;
            for (wchar_t c : wname) {
                if (c == L'"') escaped_name += L"\\\"";
                else if (c == L'\\') escaped_name += L"\\\\";
                else escaped_name += c;
            }

            file << L"    {\n";
            file << L"      \"name\": \"" << escaped_name << L"\",\n";
            file << L"      \"rva\": \"0x" << std::hex << symbol.rva << L"\",\n";
            file << L"      \"size\": " << std::dec << symbol.size << L",\n";
            file << L"      \"type_id\": " << symbol.typeId << L"\n";
            file << L"    }";

            if (i < symbols.size() - 1) file << L",";
            file << L"\n";
        }

        file << L"  ],\n";

        auto structNames = GetAllStructNames();
        file << L"  \"structures\": [\n";

        for (size_t i = 0; i < structNames.size(); ++i) {
            auto structInfo = GetStructInfo(structNames[i]);
            if (!structInfo) continue;

            file << L"    {\n";
            file << L"      \"name\": \"" << structNames[i] << L"\",\n";
            file << L"      \"size\": " << structInfo->size << L",\n";
            file << L"      \"members\": [\n";

            for (size_t j = 0; j < structInfo->members.size(); ++j) {
                const auto& member = structInfo->members[j];
                std::wstring wmemberName(member.name.begin(), member.name.end());

                file << L"        {\n";
                file << L"          \"name\": \"" << wmemberName << L"\",\n";
                file << L"          \"offset\": " << member.offset << L",\n";
                file << L"          \"size\": " << member.size << L",\n";
                file << L"          \"type_id\": " << member.typeId << L"\n";
                file << L"        }";

                if (j < structInfo->members.size() - 1) file << L",";
                file << L"\n";
            }

            file << L"      ]\n";
            file << L"    }";

            if (i < structNames.size() - 1) file << L",";
            file << L"\n";
        }

        file << L"  ],\n";
        file << L"  \"statistics\": {\n";
        file << L"    \"total_symbols\": " << symbols.size() << L",\n";
        file << L"    \"total_structures\": " << structNames.size() << L"\n";
        file << L"  }\n";
        file << L"}\n";

        return true;

    }
    catch (...) {
        return false;
    }
}

std::vector<SymbolDiff> PdbComparer::ComparePdbs(const PdbParser& oldPdb, const PdbParser& newPdb) {
    std::vector<SymbolDiff> diffs;

    auto oldSymbols = oldPdb.GetAllPublicSymbols();
    auto newSymbols = newPdb.GetAllPublicSymbols();

    std::unordered_map<std::string, DWORD64> oldMap;
    std::unordered_map<std::string, DWORD64> newMap;

    for (const auto& sym : oldSymbols) {
        oldMap[sym.name] = sym.rva;
    }

    for (const auto& sym : newSymbols) {
        newMap[sym.name] = sym.rva;
    }

    for (const auto& [name, rva] : oldMap) {
        if (newMap.find(name) == newMap.end()) {
            diffs.push_back({ name, rva, 0, false, true, false });
        }
    }

    for (const auto& [name, newRva] : newMap) {
        auto oldIt = oldMap.find(name);
        if (oldIt == oldMap.end()) {
            // Added symbol
            diffs.push_back({ name, 0, newRva, true, false, false });
        }
        else if (oldIt->second != newRva) {
            // Changed symbol
            diffs.push_back({ name, oldIt->second, newRva, false, false, true });
        }
    }

    return diffs;
}

void PdbComparer::PrintDifferences(const std::vector<SymbolDiff>& diffs) {
    std::cout << "\nPDB Comparison Results:\n";
    std::cout << std::string(60, '=') << "\n";

    int added = 0, removed = 0, changed = 0;

    for (const auto& diff : diffs) {
        if (diff.added) {
            std::cout << "[+] ADDED: " << diff.name << " at 0x" << std::hex << diff.newRva << "\n";
            added++;
        }
        else if (diff.removed) {
            std::cout << "[-] REMOVED: " << diff.name << " (was at 0x" << std::hex << diff.oldRva << ")\n";
            removed++;
        }
        else if (diff.changed) {
            std::cout << "[~] CHANGED: " << diff.name << " 0x" << std::hex << diff.oldRva
                << " -> 0x" << diff.newRva << "\n";
            changed++;
        }
    }

    std::cout << std::dec << "\nSummary: " << added << " added, "
        << removed << " removed, " << changed << " changed\n";
}

bool PdbComparer::ExportDifferencesToJson(const std::vector<SymbolDiff>& diffs, const std::wstring& outputPath) {
    try {
        std::wofstream file(outputPath);
        if (!file.is_open()) return false;

        file << L"{\n  \"differences\": [\n";

        for (size_t i = 0; i < diffs.size(); ++i) {
            const auto& diff = diffs[i];
            std::wstring name(diff.name.begin(), diff.name.end());

            file << L"    {\n";
            file << L"      \"name\": \"" << name << L"\",\n";
            file << L"      \"old_rva\": \"0x" << std::hex << diff.oldRva << L"\",\n";
            file << L"      \"new_rva\": \"0x" << std::hex << diff.newRva << L"\",\n";
            file << L"      \"status\": \"" << (diff.added ? L"added" : diff.removed ? L"removed" : L"changed") << L"\"\n";
            file << L"    }";

            if (i < diffs.size() - 1) file << L",";
            file << L"\n";
        }

        file << L"  ]\n}\n";
        return true;

    }
    catch (...) {
        return false;
    }
}

void BatchProcessor::ProcessDirectory(const std::wstring& directory, const std::wstring& outputDir) {
    std::vector<std::wstring> pdbFiles;

    try {
        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            if (entry.path().extension() == L".pdb") {
                pdbFiles.push_back(entry.path().wstring());
            }
        }

        ProcessMultiplePdbs(pdbFiles, outputDir);

    }
    catch (const std::exception& e) {
        std::cerr << "Error processing directory: " << e.what() << std::endl;
    }
}

void BatchProcessor::ProcessMultiplePdbs(const std::vector<std::wstring>& pdbFiles, const std::wstring& outputDir) {
    std::filesystem::create_directories(outputDir);

    for (const auto& pdbFile : pdbFiles) {
        try {
            std::wcout << L"Processing: " << pdbFile << L"\n";

            PdbParser parser(pdbFile);
            if (!parser.IsInitialized()) {
                std::wcout << L"Failed to initialize: " << pdbFile << L"\n";
                continue;
            }

            auto filename = std::filesystem::path(pdbFile).stem().wstring();
            auto outputFile = outputDir + L"\\" + filename + L"_analysis.json";

            if (parser.DumpToJson(outputFile)) {
                std::wcout << L"Exported: " << outputFile << L"\n";
            }

        }
        catch (const std::exception& e) {
            std::cerr << "Error processing " << std::string(pdbFile.begin(), pdbFile.end())
                << ": " << e.what() << std::endl;
        }
    }
}

void BatchProcessor::GenerateSummaryReport(const std::vector<std::wstring>& pdbFiles, const std::wstring& outputPath) {
    try {
        std::wofstream file(outputPath);
        if (!file.is_open()) return;

        file << L"{\n  \"summary\": {\n";
        file << L"    \"total_files\": " << pdbFiles.size() << L",\n";
        file << L"    \"processed\": [\n";

        for (size_t i = 0; i < pdbFiles.size(); ++i) {
            try {
                PdbParser parser(pdbFiles[i]);
                if (parser.IsInitialized()) {
                    auto symbols = parser.GetAllPublicSymbols();
                    auto structs = parser.GetAllStructNames();

                    file << L"      {\n";
                    file << L"        \"file\": \"" << pdbFiles[i] << L"\",\n";
                    file << L"        \"symbols\": " << symbols.size() << L",\n";
                    file << L"        \"structures\": " << structs.size() << L"\n";
                    file << L"      }";

                    if (i < pdbFiles.size() - 1) file << L",";
                    file << L"\n";
                }
            }
            catch (...) {
                // Skip failed files
            }
        }

        file << L"    ]\n  }\n}\n";

    }
    catch (...) {
        // Failed to create summary
    }
}
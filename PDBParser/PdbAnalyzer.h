#pragma once
#include "PdbParser.h"
#include <memory>
#include <string>
#include <fstream>

class PdbAnalyzer {
private:
    std::unique_ptr<PdbParser> m_parser;

    void PrintHeader(const std::string& title) const;
    void PrintSymbolInfo(const SymbolInfo& symbol) const;
    void PrintStructInfo(const StructInfo& structInfo) const;

public:
    explicit PdbAnalyzer(const std::wstring& pdbPath);
    ~PdbAnalyzer() = default;

    PdbAnalyzer(const PdbAnalyzer&) = delete;
    PdbAnalyzer& operator=(const PdbAnalyzer&) = delete;
    PdbAnalyzer(PdbAnalyzer&&) = default;
    PdbAnalyzer& operator=(PdbAnalyzer&&) = default;

    void ShowBasicInfo() const;
    void AnalyzeSymbols(size_t maxResults = 50) const;
    void FindSpecificSymbol(const std::wstring& symbolName) const;
    void AnalyzeStructure(const std::wstring& structName) const;
    void FindStructMember(const std::wstring& structName, const std::wstring& memberName) const;
    void SearchByPattern(const std::wstring& pattern, size_t maxResults = 20) const;
    void PerformanceTest() const;
    void ListStructures(size_t maxResults = 30) const;
    void ExportResults(const std::wstring& outputPath) const;
    bool DumpToJson(const std::wstring& outputPath) const;
};
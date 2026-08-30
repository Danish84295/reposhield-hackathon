#pragma once

#include "../core/FileScanner.h"

#include <cstddef>
#include <string>
#include <vector>

enum class DependencyType {
    Standard,
    Local,
    External
};

struct DependencyInfo {
    DependencyType type;
    std::string name;
    fs::path file;
    std::size_t line;

    std::string risk;
    std::string riskReason;
};

class DependencyAnalyzer {
public:
    std::vector<DependencyInfo> analyze(
        const std::vector<FileInfo>& files
    ) const;

    static std::string typeToString(
        DependencyType type
    );

    static std::string riskToString(
        DependencyType type
    );

    static std::string riskReason(
        DependencyType type
    );

private:
    void analyzeFile(
        const FileInfo& file,
        std::vector<DependencyInfo>& dependencies
    ) const;

    static bool parseInclude(
        const std::string& line,
        std::string& dependency,
        DependencyType& type
    );

    static std::string trim(
        const std::string& value
    );

    static bool isStandardHeader(
        const std::string& dependency
    );
};
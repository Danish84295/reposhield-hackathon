#pragma once

#include "../core/FileScanner.h"

#include <cstddef>
#include <string>
#include <vector>

enum class Severity {
    Low,
    Medium,
    High,
    Critical
};

struct SecurityIssue {
    Severity severity;
    std::string ruleId;
    std::string title;
    std::string description;
    fs::path file;
    std::size_t line;
};

class SecurityAnalyzer {
private:
    void analyzeFile(
        const FileInfo& file,
        std::vector<SecurityIssue>& issues
    ) const;

    void checkDangerousFunctions(
        const FileInfo& file,
        const std::vector<std::string>& lines,
        std::vector<SecurityIssue>& issues
    ) const;

    void checkCommandExecution(
        const FileInfo& file,
        const std::vector<std::string>& lines,
        std::vector<SecurityIssue>& issues
    ) const;

    void checkHardcodedSecrets(
        const FileInfo& file,
        const std::vector<std::string>& lines,
        std::vector<SecurityIssue>& issues
    ) const;

        void checkWeakCryptography(
        const FileInfo& file,
        const std::vector<std::string>& lines,
        std::vector<SecurityIssue>& issues
    ) const;

    void checkDangerousFileOperations(
        const FileInfo& file,
        const std::vector<std::string>& lines,
        std::vector<SecurityIssue>& issues
    ) const;

    void checkSqlInjection(
        const FileInfo& file,
        const std::vector<std::string>& lines,
        std::vector<SecurityIssue>& issues
    ) const;

    void checkInsecureRandom(
        const FileInfo& file,
        const std::vector<std::string>& lines,
        std::vector<SecurityIssue>& issues
    ) const;

    static std::vector<std::string> readLines(
        const fs::path& path
    );
    
    public:
    std::vector<SecurityIssue> analyze(
        const std::vector<FileInfo>& files
    ) const;

    static std::string severityToString(
        Severity severity
    );

};
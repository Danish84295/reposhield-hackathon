#pragma once

#include "../security/SecurityAnalyzer.h"

#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct GitStatus {
    bool isRepository = false;
    std::string branch;
    bool clean = true;

    int modifiedFiles = 0;
    int untrackedFiles = 0;
    int stagedFiles = 0;
    int trackedFiles = 0;
    int commitCount = 0;

    std::string latestCommitHash;
    std::string latestCommitMessage;

    std::vector<std::string> changedFiles;
};

struct GitSecurityImpact {
    int changedSecurityFiles = 0;

    int critical = 0;
    int high = 0;
    int medium = 0;
    int low = 0;

    std::vector<SecurityIssue> issues;
    std::vector<std::string> securityFiles;
};

class GitAnalyzer {
public:
    GitStatus analyze(const fs::path& repositoryPath) const;

    GitSecurityImpact analyzeSecurityImpact(
        const GitStatus& status,
        const std::vector<SecurityIssue>& issues
    ) const;

    void print(const GitStatus& status) const;

    void printSecurityImpact(
        const GitSecurityImpact& impact
    ) const;

private:
    static std::string runCommand(
        const fs::path& repositoryPath,
        const std::string& command
    );

    static std::string trim(
        const std::string& value
    );
};
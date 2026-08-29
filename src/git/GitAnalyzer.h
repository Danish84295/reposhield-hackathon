#pragma once

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
};

class GitAnalyzer {
public:
    GitStatus analyze(const fs::path& repositoryPath) const;

    void print(const GitStatus& status) const;

private:
    static std::string runCommand(
        const fs::path& repositoryPath,
        const std::string& command
    );

    static std::string trim(
        const std::string& value
    );
};

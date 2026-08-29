#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "FileScanner.h"

enum class Language {
    Cpp,
    C,
    Python,
    JavaScript,
    TypeScript,
    Java,
    Unknown
};

struct LanguageStats {
    Language language;
    std::size_t files;
    std::size_t lines;
};

struct RepositoryStats {
    std::size_t totalFiles;
    std::size_t sourceFiles;
    std::size_t headerFiles;
    std::uintmax_t totalBytes;
    std::size_t totalLines;

    std::vector<LanguageStats> languages;
};

class RepositoryStatsAnalyzer {
public:
    RepositoryStats analyze(
        const std::vector<FileInfo>& files
    ) const;

    static std::string languageToString(Language language);

private:
    Language detectLanguage(const fs::path& path) const;

    bool isHeaderFile(const fs::path& path) const;

    std::size_t countLines(const fs::path& path) const;
};

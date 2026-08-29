#include "RepositoryStats.h"

#include <fstream>
#include <map>
#include <string>

RepositoryStats RepositoryStatsAnalyzer::analyze(
    const std::vector<FileInfo>& files
) const
{
    RepositoryStats stats{};

    stats.totalFiles = files.size();

    std::map<Language, LanguageStats> languageMap;

    for (const FileInfo& file : files) {

        stats.totalBytes += file.size;

        const Language language =
            detectLanguage(file.path);

        const std::size_t lines =
            countLines(file.path);

        stats.totalLines += lines;

        if (isHeaderFile(file.path)) {
            ++stats.headerFiles;
        } else {
            ++stats.sourceFiles;
        }

        auto it = languageMap.find(language);

        if (it == languageMap.end()) {

            languageMap[language] = {
                language,
                1,
                lines
            };

        } else {

            ++it->second.files;
            it->second.lines += lines;
        }
    }

    for (const auto& entry : languageMap) {
        stats.languages.push_back(entry.second);
    }

    return stats;
}

Language RepositoryStatsAnalyzer::detectLanguage(
    const fs::path& path
) const
{
    const std::string extension =
        path.extension().string();

    if (
        extension == ".cpp" ||
        extension == ".cc" ||
        extension == ".cxx" ||
        extension == ".hpp" ||
        extension == ".hh"
    ) {
        return Language::Cpp;
    }

    if (extension == ".c") {
        return Language::C;
    }

    if (extension == ".h") {
        return Language::Cpp;
    }

    if (extension == ".py") {
        return Language::Python;
    }

    if (
        extension == ".js" ||
        extension == ".jsx"
    ) {
        return Language::JavaScript;
    }

    if (
        extension == ".ts" ||
        extension == ".tsx"
    ) {
        return Language::TypeScript;
    }

    if (extension == ".java") {
        return Language::Java;
    }

    return Language::Unknown;
}

bool RepositoryStatsAnalyzer::isHeaderFile(
    const fs::path& path
) const
{
    const std::string extension =
        path.extension().string();

    return
        extension == ".h" ||
        extension == ".hpp" ||
        extension == ".hh";
}

std::size_t RepositoryStatsAnalyzer::countLines(
    const fs::path& path
) const
{
    std::ifstream file(path);

    if (!file.is_open()) {
        return 0;
    }

    std::size_t lines = 0;
    std::string line;

    while (std::getline(file, line)) {
        ++lines;
    }

    return lines;
}

std::string RepositoryStatsAnalyzer::languageToString(
    Language language
)
{
    switch (language) {

        case Language::Cpp:
            return "C++";

        case Language::C:
            return "C";

        case Language::Python:
            return "Python";

        case Language::JavaScript:
            return "JavaScript";

        case Language::TypeScript:
            return "TypeScript";

        case Language::Java:
            return "Java";

        default:
            return "Unknown";
    }
}

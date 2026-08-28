#include "CodeLens.h"

#include <fstream>
#include <iterator>
#include <regex>

std::string CodeLens::readFile(
    const fs::path& path
) const
{
    std::ifstream file(path);

    if (!file) {
        return {};
    }

    return std::string(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

CodeLensResult CodeLens::analyze(
    const std::vector<FileInfo>& files
) const
{
    CodeLensResult result;

    for (const FileInfo& file : files) {

        const std::string content =
            readFile(file.path);

        if (content.empty()) {
            continue;
        }

        result.includeCount +=
            countIncludes(content);

        result.functionCount +=
            countFunctions(content);

        result.classCount +=
            countClasses(content);

        result.structCount +=
            countStructs(content);
    }

    return result;
}

std::size_t CodeLens::countIncludes(
    const std::string& content
) const
{
    const std::regex pattern(
        R"(#\s*include\s*[<"][^>"]+[>"])"
    );

    std::size_t count = 0;

    std::sregex_iterator begin(
        content.begin(),
        content.end(),
        pattern
    );

    const std::sregex_iterator end;

    for (auto it = begin; it != end; ++it) {
        ++count;
    }

    return count;
}

std::size_t CodeLens::countFunctions(
    const std::string& content
) const
{
    const std::regex pattern(
        R"(\b[A-Za-z_][A-Za-z0-9_:<>*&\s]*\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^;{}]*\)\s*\{)"
    );

    std::size_t count = 0;

    std::sregex_iterator begin(
        content.begin(),
        content.end(),
        pattern
    );

    const std::sregex_iterator end;

    for (auto it = begin; it != end; ++it) {
        ++count;
    }

    return count;
}

std::size_t CodeLens::countClasses(
    const std::string& content
) const
{
    const std::regex pattern(
        R"(\bclass\s+[A-Za-z_][A-Za-z0-9_]*)"
    );

    std::size_t count = 0;

    std::sregex_iterator begin(
        content.begin(),
        content.end(),
        pattern
    );

    const std::sregex_iterator end;

    for (auto it = begin; it != end; ++it) {
        ++count;
    }

    return count;
}

std::size_t CodeLens::countStructs(
    const std::string& content
) const
{
    const std::regex pattern(
        R"(\bstruct\s+[A-Za-z_][A-Za-z0-9_]*)"
    );

    std::size_t count = 0;

    std::sregex_iterator begin(
        content.begin(),
        content.end(),
        pattern
    );

    const std::sregex_iterator end;

    for (auto it = begin; it != end; ++it) {
        ++count;
    }

    return count;
}
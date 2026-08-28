#pragma once

#include "../core/FileScanner.h"

#include <cstddef>
#include <string>
#include <vector>

struct CodeLensResult {
    std::size_t includeCount = 0;
    std::size_t functionCount = 0;
    std::size_t classCount = 0;
    std::size_t structCount = 0;
};

class CodeLens {
public:
    CodeLensResult analyze(
        const std::vector<FileInfo>& files
    ) const;

private:
    std::string readFile(
        const fs::path& path
    ) const;

    std::size_t countIncludes(
        const std::string& content
    ) const;

    std::size_t countFunctions(
        const std::string& content
    ) const;

    std::size_t countClasses(
        const std::string& content
    ) const;

    std::size_t countStructs(
        const std::string& content
    ) const;
};
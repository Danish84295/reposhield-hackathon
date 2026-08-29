#pragma once

#include "../core/FileScanner.h"

#include <cstddef>
#include <string>
#include <vector>

struct FunctionInfo {
    std::string name;
    fs::path file;
    std::size_t line = 0;
    std::size_t lines = 0;
};

struct ClassInfo {
    std::string name;
    fs::path file;
    std::size_t line = 0;
    std::size_t methods = 0;
};

struct StructInfo {
    std::string name;
    fs::path file;
    std::size_t line = 0;
};

struct CodeLensResult {
    std::size_t includeCount = 0;
    std::size_t functionCount = 0;
    std::size_t classCount = 0;
    std::size_t structCount = 0;

    std::vector<FunctionInfo> functions;
    std::vector<ClassInfo> classes;
    std::vector<StructInfo> structs;
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

    std::vector<FunctionInfo> detectFunctions(
        const std::string& content,
        const fs::path& file
    ) const;

    std::vector<ClassInfo> detectClasses(
        const std::string& content,
        const fs::path& file
    ) const;

    std::vector<StructInfo> detectStructs(
        const std::string& content,
        const fs::path& file
    ) const;

    std::size_t lineNumber(
        const std::string& content,
        std::size_t position
    ) const;

    std::size_t blockLineCount(
        const std::string& content,
        std::size_t openingBrace
    ) const;
};

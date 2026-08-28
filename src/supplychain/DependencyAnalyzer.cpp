#include "DependencyAnalyzer.h"

#include <fstream>
#include <sstream>

std::vector<DependencyInfo> DependencyAnalyzer::analyze(
    const std::vector<FileInfo>& files
) const
{
    std::vector<DependencyInfo> dependencies;

    for (const FileInfo& file : files) {
        analyzeFile(file, dependencies);
    }

    return dependencies;
}

void DependencyAnalyzer::analyzeFile(
    const FileInfo& file,
    std::vector<DependencyInfo>& dependencies
) const
{
    std::ifstream input(file.path);

    if (!input.is_open()) {
        return;
    }

    std::string line;
    std::size_t lineNumber = 0;

    while (std::getline(input, line)) {
        ++lineNumber;

        std::string dependency;
        DependencyType type;

        if (parseInclude(line, dependency, type)) {
            dependencies.push_back({
                type,
                dependency,
                file.path,
                lineNumber
            });
        }
    }
}

bool DependencyAnalyzer::parseInclude(
    const std::string& line,
    std::string& dependency,
    DependencyType& type
)
{
    const std::string trimmed = trim(line);

    if (trimmed.rfind("#include", 0) != 0) {
        return false;
    }

    const std::size_t position = 8;

    if (trimmed.size() <= position) {
        return false;
    }

    const std::string target =
        trim(trimmed.substr(position));

    if (target.size() < 3) {
        return false;
    }

    // Local project dependency:
    // #include "parser.h"
    if (target.front() == '"' &&
        target.back() == '"') {

        dependency =
            target.substr(1, target.size() - 2);

        type = DependencyType::Local;

        return !dependency.empty();
    }

    // Header supplied through system/compiler include paths:
    // #include <iostream>
    if (target.front() == '<' &&
        target.back() == '>') {

        dependency =
            target.substr(1, target.size() - 2);

        /*
         * For this first version, standard C/C++ headers
         * are classified as Standard. Later we can maintain
         * a known external-package database.
         */
        type = DependencyType::Standard;

        return !dependency.empty();
    }

    return false;
}

std::string DependencyAnalyzer::typeToString(
    DependencyType type
)
{
    switch (type) {

        case DependencyType::Standard:
            return "STANDARD";

        case DependencyType::Local:
            return "LOCAL";

        case DependencyType::External:
            return "EXTERNAL";
    }

    return "UNKNOWN";
}

std::string DependencyAnalyzer::trim(
    const std::string& value
)
{
    const std::string whitespace = " \t\r\n";

    const std::size_t start =
        value.find_first_not_of(whitespace);

    if (start == std::string::npos) {
        return "";
    }

    const std::size_t end =
        value.find_last_not_of(whitespace);

    return value.substr(
        start,
        end - start + 1
    );
}
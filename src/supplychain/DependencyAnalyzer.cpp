#include "DependencyAnalyzer.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <vector>

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
                lineNumber,
                riskToString(type),
                riskReason(type)
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

    // ------------------------------------------------------------
    // Local project dependency
    //
    // Example:
    // #include "parser.h"
    // ------------------------------------------------------------

    if (target.front() == '"' &&
        target.back() == '"') {

        dependency =
            target.substr(1, target.size() - 2);

        type = DependencyType::Local;

        return !dependency.empty();
    }

    // ------------------------------------------------------------
    // System / external dependency
    //
    // Examples:
    // #include <iostream>
    // #include <openssl/ssl.h>
    // #include <curl/curl.h>
    // ------------------------------------------------------------

    if (target.front() == '<' &&
        target.back() == '>') {

        dependency =
            target.substr(1, target.size() - 2);

        if (dependency.empty()) {
            return false;
        }

        if (isStandardHeader(dependency)) {
            type = DependencyType::Standard;
        }
        else {
            type = DependencyType::External;
        }

        return true;
    }

    return false;
}

// ------------------------------------------------------------
// Standard C/C++ header detection
// ------------------------------------------------------------

bool DependencyAnalyzer::isStandardHeader(
    const std::string& dependency
)
{
    static const std::vector<std::string> standardHeaders = {

        "algorithm",
        "array",
        "atomic",
        "bitset",
        "cassert",
        "cctype",
        "cerrno",
        "cfenv",
        "cfloat",
        "charconv",
        "chrono",
        "cinttypes",
        "ciso646",
        "climits",
        "clocale",
        "cmath",
        "codecvt",
        "compare",
        "complex",
        "concepts",
        "condition_variable",
        "coroutine",
        "csetjmp",
        "csignal",
        "cstdarg",
        "cstddef",
        "cstdint",
        "cstdio",
        "cstdlib",
        "cstring",
        "ctgmath",
        "ctime",
        "cuchar",
        "cwchar",
        "cwctype",

        "deque",
        "exception",
        "execution",

        "filesystem",
        "forward_list",
        "fstream",
        "functional",
        "future",

        "initializer_list",
        "iomanip",
        "ios",
        "iosfwd",
        "iostream",
        "istream",
        "iterator",

        "latch",
        "limits",
        "list",
        "locale",

        "map",
        "memory",
        "memory_resource",
        "mutex",

        "new",
        "numbers",
        "numeric",

        "optional",
        "ostream",

        "queue",

        "random",
        "ranges",
        "ratio",
        "regex",
        "scoped_allocator",

        "semaphore",
        "set",
        "shared_mutex",
        "source_location",
        "span",
        "sstream",
        "stack",
        "stdexcept",
        "streambuf",
        "string",
        "string_view",
        "syncstream",

        "system_error",

        "thread",
        "tuple",
        "type_traits",
        "typeindex",
        "typeinfo",

        "unordered_map",
        "unordered_set",
        "utility",

        "valarray",
        "variant",
        "vector",

        "version"
    };

    return std::find(
        standardHeaders.begin(),
        standardHeaders.end(),
        dependency
    ) != standardHeaders.end();
}

// ------------------------------------------------------------
// Dependency risk
// ------------------------------------------------------------

std::string DependencyAnalyzer::riskToString(
    DependencyType type
)
{
    switch (type) {

        case DependencyType::Standard:
            return "LOW";

        case DependencyType::Local:
            return "LOW";

        case DependencyType::External:
            return "MEDIUM";
    }

    return "UNKNOWN";
}

// ------------------------------------------------------------
// Dependency risk explanation
// ------------------------------------------------------------

std::string DependencyAnalyzer::riskReason(
    DependencyType type
)
{
    switch (type) {

        case DependencyType::Standard:
            return
                "Standard library dependency with low supply-chain risk.";

        case DependencyType::Local:
            return
                "Local project dependency; risk depends on repository contents.";

        case DependencyType::External:
            return
                "External dependency should be reviewed for version, "
                "provenance, and known vulnerabilities.";
    }

    return "Unknown dependency risk.";
}

// ------------------------------------------------------------
// Dependency type
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// Trim whitespace
// ------------------------------------------------------------

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
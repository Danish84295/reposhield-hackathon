#include "SecurityAnalyzer.h"

#include <fstream>
#include <regex>

std::vector<std::string> SecurityAnalyzer::readLines(
    const fs::path& path
)
{
    std::vector<std::string> lines;

    std::ifstream file(path);

    if (!file) {
        return lines;
    }

    std::string line;

    while (std::getline(file, line)) {
        lines.push_back(line);
    }

    return lines;
}

std::vector<SecurityIssue> SecurityAnalyzer::analyze(
    const std::vector<FileInfo>& files
) const
{
    std::vector<SecurityIssue> issues;

    for (const FileInfo& file : files) {
        analyzeFile(file, issues);
    }

    return issues;
}

void SecurityAnalyzer::analyzeFile(
    const FileInfo& file,
    std::vector<SecurityIssue>& issues
) const
{
    const std::vector<std::string> lines =
        readLines(file.path);

    if (lines.empty()) {
        return;
    }

    checkDangerousFunctions(
        file,
        lines,
        issues
    );

    checkCommandExecution(
        file,
        lines,
        issues
    );

    checkHardcodedSecrets(
        file,
        lines,
        issues
    );
}

void SecurityAnalyzer::checkDangerousFunctions(
    const FileInfo& file,
    const std::vector<std::string>& lines,
    std::vector<SecurityIssue>& issues
) const
{
    const std::regex dangerousFunctions(
        R"(\b(strcpy|strcat|sprintf|gets)\s*\()"
    );

    for (std::size_t i = 0; i < lines.size(); ++i) {

        if (std::regex_search(
                lines[i],
                dangerousFunctions)) {

            issues.push_back({
                Severity::High,
                "RS001",
                "Unsafe C string function",
                "Use of an unsafe C string function can cause "
                "buffer overflows and memory corruption.",
                file.path,
                i + 1
            });
        }
    }
}

void SecurityAnalyzer::checkCommandExecution(
    const FileInfo& file,
    const std::vector<std::string>& lines,
    std::vector<SecurityIssue>& issues
) const
{
    const std::regex commandExecution(
        R"(\b(system|popen)\s*\()"
    );

    for (std::size_t i = 0; i < lines.size(); ++i) {

        if (std::regex_search(
                lines[i],
                commandExecution)) {

            issues.push_back({
                Severity::High,
                "RS002",
                "Command execution detected",
                "Executing operating-system commands can introduce "
                "command injection vulnerabilities when input is not trusted.",
                file.path,
                i + 1
            });
        }
    }
}

void SecurityAnalyzer::checkHardcodedSecrets(
    const FileInfo& file,
    const std::vector<std::string>& lines,
    std::vector<SecurityIssue>& issues
) const
{
    const std::regex secretPattern(
        R"((password|passwd|api_key|apikey|secret|token)\s*=\s*["'][^"']+["'])",
        std::regex_constants::icase
    );

    for (std::size_t i = 0; i < lines.size(); ++i) {

        if (std::regex_search(
                lines[i],
                secretPattern)) {

            issues.push_back({
                Severity::Critical,
                "RS003",
                "Possible hardcoded secret",
                "A credential-like value appears to be stored directly "
                "in source code.",
                file.path,
                i + 1
            });
        }
    }
}

std::string SecurityAnalyzer::severityToString(
    Severity severity
)
{
    switch (severity) {

        case Severity::Low:
            return "LOW";

        case Severity::Medium:
            return "MEDIUM";

        case Severity::High:
            return "HIGH";

        case Severity::Critical:
            return "CRITICAL";
    }

    return "UNKNOWN";
}
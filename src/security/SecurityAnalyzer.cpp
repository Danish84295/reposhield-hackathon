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
        checkWeakCryptography(
        file,
        lines,
        issues
    );

    checkDangerousFileOperations(
        file,
        lines,
        issues
    );

    checkSqlInjection(
        file,
        lines,
        issues
    );

    checkInsecureRandom(
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

void SecurityAnalyzer::checkWeakCryptography(
    const FileInfo& file,
    const std::vector<std::string>& lines,
    std::vector<SecurityIssue>& issues
) const
{
    const std::regex weakCrypto(
        R"(\b(MD5|MD4|SHA1|SHA-1|DES|RC4)\b)",
        std::regex_constants::icase
    );

    for (std::size_t i = 0; i < lines.size(); ++i) {

        if (std::regex_search(lines[i], weakCrypto)) {

            issues.push_back({
                Severity::High,
                "RS004",
                "Weak cryptographic algorithm",
                "Use of a weak or deprecated cryptographic algorithm "
                "can make sensitive data vulnerable to attacks. "
                "Prefer modern algorithms such as SHA-256 or stronger "
                "authenticated encryption where appropriate.",
                file.path,
                i + 1
            });
        }
    }
}

void SecurityAnalyzer::checkDangerousFileOperations(
    const FileInfo& file,
    const std::vector<std::string>& lines,
    std::vector<SecurityIssue>& issues
) const
{
    const std::regex dangerousFileOperation(
        R"(\b(fopen|open|remove|rename)\s*\()"
    );

    for (std::size_t i = 0; i < lines.size(); ++i) {

        if (std::regex_search(
                lines[i],
                dangerousFileOperation)) {

            issues.push_back({
                Severity::Medium,
                "RS005",
                "Potentially dangerous file operation",
                "File operations can introduce security risks when "
                "paths or filenames are controlled by untrusted input. "
                "Validate paths and restrict access to expected locations.",
                file.path,
                i + 1
            });
        }
    }
}

void SecurityAnalyzer::checkSqlInjection(
    const FileInfo& file,
    const std::vector<std::string>& lines,
    std::vector<SecurityIssue>& issues
) const
{
    const std::regex sqlPattern(
        R"((SELECT|INSERT|UPDATE|DELETE)\b.*(\+|<<|sprintf|format\s*\())",
        std::regex_constants::icase
    );

    for (std::size_t i = 0; i < lines.size(); ++i) {

        if (std::regex_search(
                lines[i],
                sqlPattern)) {

            issues.push_back({
                Severity::High,
                "RS006",
                "Potential SQL injection",
                "SQL statements appear to be constructed using "
                "string concatenation or formatting. Use parameterized "
                "queries or prepared statements instead.",
                file.path,
                i + 1
            });
        }
    }
}

void SecurityAnalyzer::checkInsecureRandom(
    const FileInfo& file,
    const std::vector<std::string>& lines,
    std::vector<SecurityIssue>& issues
) const
{
    const std::regex insecureRandom(
        R"(\b(srand|rand)\s*\()"
    );

    for (std::size_t i = 0; i < lines.size(); ++i) {

        if (std::regex_search(
                lines[i],
                insecureRandom)) {

            issues.push_back({
                Severity::Medium,
                "RS007",
                "Insecure random number generation",
                "The rand()/srand() pseudo-random generator is not "
                "suitable for security-sensitive values. Use a "
                "cryptographically secure random generator instead.",
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
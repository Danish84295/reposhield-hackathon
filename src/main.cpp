#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "core/FileScanner.h"
#include "codelens/CodeLens.h"
#include "security/SecurityAnalyzer.h"
#include "supplychain/DependencyAnalyzer.h"

namespace fs = std::filesystem;

void printUsage()
{
    std::cout
        << "RepoShield - Zero-Dependency Repository Intelligence\n\n"
        << "Usage:\n"
        << "  reposhield analyze <path>\n";
}

void printSecurityReport(
    const std::vector<SecurityIssue>& issues
)
{
    std::cout
        << "----------------------------------------\n"
        << "              SECURITY\n"
        << "----------------------------------------\n\n";

    std::cout
        << "Issues found: "
        << issues.size()
        << "\n\n";

    if (issues.empty()) {
        std::cout
            << "No security issues detected.\n\n";

        return;
    }

    for (const SecurityIssue& issue : issues) {

        std::cout
            << "["
            << issue.ruleId
            << "] "
            << issue.title
            << "\n";

        std::cout
            << "  Severity: "
            << SecurityAnalyzer::severityToString(
                   issue.severity
               )
            << "\n";

        std::cout
            << "  File: "
            << issue.file.string()
            << "\n";

        std::cout
            << "  Line: "
            << issue.line
            << "\n";

        std::cout
            << "  "
            << issue.description
            << "\n\n";
    }
}

void printSupplyChainReport(
    const std::vector<DependencyInfo>& dependencies
)
{
    std::cout
        << "----------------------------------------\n"
        << "           SUPPLY CHAIN\n"
        << "----------------------------------------\n\n";

    std::cout
        << "Dependencies found: "
        << dependencies.size()
        << "\n\n";

    if (dependencies.empty()) {
        std::cout
            << "No dependencies detected.\n\n";

        return;
    }

    for (const DependencyInfo& dependency : dependencies) {

        std::cout
            << "["
            << DependencyAnalyzer::typeToString(
                   dependency.type
               )
            << "] "
            << dependency.name
            << "\n";

        std::cout
            << "  File: "
            << dependency.file.string()
            << "\n";

        std::cout
            << "  Line: "
            << dependency.line
            << "\n\n";
    }
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printUsage();
        return 1;
    }

    const std::string command = argv[1];

    if (command != "analyze") {
        std::cerr
            << "Error: unknown command '"
            << command
            << "'\n\n";

        printUsage();
        return 1;
    }

    if (argc < 3) {
        std::cerr
            << "Error: repository path is required.\n\n";

        printUsage();
        return 1;
    }

    const fs::path repositoryPath = argv[2];

    // ------------------------------------------------------------
    // Repository scanning
    // ------------------------------------------------------------

    FileScanner scanner;

    const std::vector<FileInfo> files =
        scanner.scan(repositoryPath);

    // ------------------------------------------------------------
    // Code analysis
    // ------------------------------------------------------------

    CodeLens codeLens;

    const CodeLensResult codeResult =
        codeLens.analyze(files);

    // ------------------------------------------------------------
    // Security analysis
    // ------------------------------------------------------------

    SecurityAnalyzer securityAnalyzer;

    const std::vector<SecurityIssue> securityIssues =
        securityAnalyzer.analyze(files);

    // ------------------------------------------------------------
    // Supply chain analysis
    // ------------------------------------------------------------

    DependencyAnalyzer dependencyAnalyzer;

    const std::vector<DependencyInfo> dependencies =
        dependencyAnalyzer.analyze(files);

    // ------------------------------------------------------------
    // Main report
    // ------------------------------------------------------------

    std::cout << "\n";

    std::cout
        << "========================================\n"
        << "              REPOSHIELD\n"
        << "========================================\n\n";

    std::cout
        << "Repository: "
        << repositoryPath.string()
        << "\n\n";

    std::cout
        << "Source files: "
        << files.size()
        << "\n\n";

    for (const FileInfo& file : files) {

        std::cout
            << "  "
            << file.path.string()
            << "  ("
            << file.size
            << " bytes)\n";
    }

    // ------------------------------------------------------------
    // Code Lens report
    // ------------------------------------------------------------

    std::cout
        << "\n"
        << "----------------------------------------\n"
        << "              CODE LENS\n"
        << "----------------------------------------\n\n";

    std::cout
        << "Includes:  "
        << codeResult.includeCount
        << "\n";

    std::cout
        << "Functions: "
        << codeResult.functionCount
        << "\n";

    std::cout
        << "Classes:   "
        << codeResult.classCount
        << "\n";

    std::cout
        << "Structs:   "
        << codeResult.structCount
        << "\n\n";

    // ------------------------------------------------------------
    // Security report
    // ------------------------------------------------------------

    printSecurityReport(securityIssues);

    // ------------------------------------------------------------
    // Supply chain report
    // ------------------------------------------------------------

    printSupplyChainReport(dependencies);

    return 0;
}
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "core/FileScanner.h"
#include "codelens/CodeLens.h"
#include "security/SecurityAnalyzer.h"
#include "supplychain/DependencyAnalyzer.h"
#include "graph/DependencyGraph.h"
#include "risk/RiskScorer.h"
#include "reporting/HealthReport.h"
#include "remediation/RemediationEngine.h"

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

void printRemediationReport(
    const std::vector<SecurityIssue>& issues,
    const std::vector<Remediation>& remediations
)
{
    std::cout
        << "----------------------------------------\n"
        << "         REMEDIATION GUIDANCE\n"
        << "----------------------------------------\n\n";

    if (issues.empty()) {
        std::cout
            << "No remediation actions required.\n\n";

        return;
    }

    for (std::size_t i = 0;
         i < issues.size() && i < remediations.size();
         ++i) {

        const SecurityIssue& issue = issues[i];
        const Remediation& remediation = remediations[i];

        std::cout
            << "["
            << remediation.ruleId
            << "] "
            << issue.title
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
            << "  Recommendation:\n"
            << "    "
            << remediation.recommendation
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
    // Remediation analysis
    // ------------------------------------------------------------

    RemediationEngine remediationEngine;

    const std::vector<Remediation> remediations =
        remediationEngine.generate(securityIssues);

    // ------------------------------------------------------------
    // Risk analysis
    // ------------------------------------------------------------

    RiskScorer riskScorer;

    const RiskSummary riskSummary =
        riskScorer.calculate(securityIssues);

    // ------------------------------------------------------------
    // Supply chain analysis
    // ------------------------------------------------------------

    DependencyAnalyzer dependencyAnalyzer;

    const std::vector<DependencyInfo> dependencies =
        dependencyAnalyzer.analyze(files);

    // ------------------------------------------------------------
    // Dependency graph
    // ------------------------------------------------------------

    DependencyGraph dependencyGraph;

    const std::vector<DependencyEdge> dependencyEdges =
        dependencyGraph.build(dependencies);

    // ------------------------------------------------------------
    // Health report
    // ------------------------------------------------------------

    HealthReportGenerator healthReportGenerator;

    const HealthReport healthReport =
        healthReportGenerator.generate(
            files.size(),
            codeResult,
            securityIssues,
            dependencies,
            riskSummary
        );

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
    // Risk report
    // ------------------------------------------------------------

    riskScorer.print(riskSummary);

    // ------------------------------------------------------------
    // Supply chain report
    // ------------------------------------------------------------

    printSupplyChainReport(dependencies);

    // ------------------------------------------------------------
    // Dependency graph report
    // ------------------------------------------------------------

    std::cout
        << "----------------------------------------\n"
        << "          DEPENDENCY GRAPH\n"
        << "----------------------------------------\n\n";

    dependencyGraph.print(dependencyEdges);

    // ------------------------------------------------------------
    // Remediation report
    // ------------------------------------------------------------

    printRemediationReport(
        securityIssues,
        remediations
    );

    // ------------------------------------------------------------
    // Final health report
    // ------------------------------------------------------------

    healthReportGenerator.print(
        healthReport,
        securityIssues
    );

    return 0;
}
#include "HealthReport.h"

#include <iostream>

HealthReport HealthReportGenerator::generate(
    std::size_t sourceFiles,
    const CodeLensResult& codeLens,
    const std::vector<SecurityIssue>& securityIssues,
    const std::vector<DependencyInfo>& dependencies,
    const RiskSummary& risk
) const
{
    HealthReport report{};

    report.sourceFiles = sourceFiles;
    report.dependencyCount = dependencies.size();
    report.securityIssueCount = securityIssues.size();

    report.codeLens = codeLens;
    report.risk = risk;

    return report;
}

void HealthReportGenerator::print(
    const HealthReport& report,
    const std::vector<SecurityIssue>& securityIssues
) const
{
    std::cout
        << "----------------------------------------\n"
        << "        REPOSITORY HEALTH REPORT\n"
        << "----------------------------------------\n\n";

    std::cout
        << "Risk Level: "
        << report.risk.level
        << "\n";

    std::cout
        << "Risk Score: "
        << report.risk.score
        << " / 100\n\n";

    std::cout
        << "Source Files:    "
        << report.sourceFiles
        << "\n";

    std::cout
        << "Dependencies:    "
        << report.dependencyCount
        << "\n";

    std::cout
        << "Security Issues: "
        << report.securityIssueCount
        << "\n\n";

    std::cout
        << "Critical: "
        << report.risk.criticalCount
        << "\n";

    std::cout
        << "High:     "
        << report.risk.highCount
        << "\n";

    std::cout
        << "Medium:   "
        << report.risk.mediumCount
        << "\n";

    std::cout
        << "Low:      "
        << report.risk.lowCount
        << "\n\n";

    if (!securityIssues.empty()) {

        std::cout
            << "Top Security Findings:\n\n";

        for (std::size_t i = 0;
             i < securityIssues.size() && i < 3;
             ++i) {

            const SecurityIssue& issue =
                securityIssues[i];

            std::cout
                << "  "
                << (i + 1)
                << ". ["
                << issue.ruleId
                << "] "
                << issue.title
                << "\n";

            std::cout
                << "     "
                << issue.file.string()
                << ":"
                << issue.line
                << "\n";
        }

        std::cout << "\n";
    }

    if (report.risk.score == 0) {

        std::cout
            << "Status: HEALTHY\n\n";

    } else if (report.risk.score < 50) {

        std::cout
            << "Status: REVIEW RECOMMENDED\n\n";

    } else {

        std::cout
            << "Status: ACTION REQUIRED\n\n";
    }
}
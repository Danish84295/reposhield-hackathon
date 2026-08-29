#include "RiskScorer.h"

#include <algorithm>
#include <iostream>

int RiskScorer::severityWeight(
    Severity severity
)
{
    switch (severity) {
        case Severity::Critical:
            return 40;

        case Severity::High:
            return 25;

        case Severity::Medium:
            return 15;

        case Severity::Low:
            return 5;
    }

    return 0;
}

std::string RiskScorer::riskLevel(
    int score
)
{
    if (score >= 75) {
        return "CRITICAL";
    }

    if (score >= 50) {
        return "HIGH";
    }

    if (score >= 25) {
        return "MEDIUM";
    }

    if (score > 0) {
        return "LOW";
    }

    return "SAFE";
}

RiskSummary RiskScorer::calculate(
    const std::vector<SecurityIssue>& issues
) const
{
    RiskSummary summary{};

    for (const SecurityIssue& issue : issues) {

        switch (issue.severity) {

            case Severity::Critical:
                ++summary.criticalCount;
                break;

            case Severity::High:
                ++summary.highCount;
                break;

            case Severity::Medium:
                ++summary.mediumCount;
                break;

            case Severity::Low:
                ++summary.lowCount;
                break;
        }

        summary.score += severityWeight(issue.severity);
    }

    // Keep the score within a simple 0-100 range.
    summary.score = std::min(summary.score, 100);

    summary.level = riskLevel(summary.score);

    return summary;
}

void RiskScorer::print(
    const RiskSummary& summary
) const
{
    std::cout
        << "----------------------------------------\n"
        << "             RISK SUMMARY\n"
        << "----------------------------------------\n\n";

    std::cout
        << "Risk Level: "
        << summary.level
        << "\n";

    std::cout
        << "Risk Score: "
        << summary.score
        << " / 100\n\n";

    std::cout
        << "Critical: "
        << summary.criticalCount
        << "\n";

    std::cout
        << "High:     "
        << summary.highCount
        << "\n";

    std::cout
        << "Medium:   "
        << summary.mediumCount
        << "\n";

    std::cout
        << "Low:      "
        << summary.lowCount
        << "\n\n";
}
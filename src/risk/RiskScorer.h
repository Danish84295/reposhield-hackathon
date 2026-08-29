#pragma once

#include "../security/SecurityAnalyzer.h"

#include <cstddef>
#include <string>
#include <vector>

struct RiskSummary {
    int score;
    std::string level;

    std::size_t criticalCount;
    std::size_t highCount;
    std::size_t mediumCount;
    std::size_t lowCount;
};

class RiskScorer {
public:
    RiskSummary calculate(
        const std::vector<SecurityIssue>& issues
    ) const;

    void print(
        const RiskSummary& summary
    ) const;

private:
    static int severityWeight(Severity severity);
    static std::string riskLevel(int score);
};
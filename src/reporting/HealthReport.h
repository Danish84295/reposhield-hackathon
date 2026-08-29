#pragma once

#include "../codelens/CodeLens.h"
#include "../risk/RiskScorer.h"
#include "../security/SecurityAnalyzer.h"
#include "../supplychain/DependencyAnalyzer.h"

#include <cstddef>
#include <vector>

struct HealthReport {
    std::size_t sourceFiles;
    std::size_t dependencyCount;
    std::size_t securityIssueCount;

    CodeLensResult codeLens;
    RiskSummary risk;
};

class HealthReportGenerator {
public:
    HealthReport generate(
        std::size_t sourceFiles,
        const CodeLensResult& codeLens,
        const std::vector<SecurityIssue>& securityIssues,
        const std::vector<DependencyInfo>& dependencies,
        const RiskSummary& risk
    ) const;

    void print(
        const HealthReport& report,
        const std::vector<SecurityIssue>& securityIssues
    ) const;
};
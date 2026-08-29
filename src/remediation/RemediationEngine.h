#pragma once

#include "../security/SecurityAnalyzer.h"

#include <string>
#include <vector>

struct Remediation {
    std::string ruleId;
    std::string recommendation;
};

struct FixResult {
    std::string ruleId;
    fs::path file;
    std::size_t line = 0;
    bool applied = false;
    std::string message;
};

class RemediationEngine {
public:
    std::vector<Remediation> generate(
        const std::vector<SecurityIssue>& issues
    ) const;

    std::vector<FixResult> fix(
        const std::vector<SecurityIssue>& issues,
        bool dryRun
    ) const;

    static std::string recommendationFor(
        const std::string& ruleId
    );

private:
    FixResult fixIssue(
        const SecurityIssue& issue,
        bool dryRun
    ) const;

    FixResult fixUnsafeCString(
        const SecurityIssue& issue,
        bool dryRun
    ) const;
};
#pragma once

#include "../security/SecurityAnalyzer.h"

#include <string>
#include <vector>

struct Remediation {
    std::string ruleId;
    std::string recommendation;
};

class RemediationEngine {
public:
    std::vector<Remediation> generate(
        const std::vector<SecurityIssue>& issues
    ) const;

    static std::string recommendationFor(
        const std::string& ruleId
    );
};
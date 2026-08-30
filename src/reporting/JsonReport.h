#pragma once

#include "../core/FileScanner.h"
#include "../codelens/CodeLens.h"
#include "../security/SecurityAnalyzer.h"
#include "../risk/RiskScorer.h"
#include "../supplychain/DependencyAnalyzer.h"
#include "../remediation/RemediationEngine.h"
#include "../git/GitAnalyzer.h"

#include <filesystem>
#include <string>
#include <vector>

class JsonReportGenerator {
public:
    bool write(
        const std::filesystem::path& outputPath,
        const std::filesystem::path& repositoryPath,
        const std::vector<FileInfo>& files,
        const CodeLensResult& codeResult,
        const std::vector<SecurityIssue>& securityIssues,
        const std::vector<DependencyInfo>& dependencies,
        const RiskSummary& riskSummary,
        const std::vector<Remediation>& remediations,
        const GitStatus& gitStatus
    ) const;

private:
    static std::string escapeJson(
        const std::string& value
    );

    static std::string severityToString(
        Severity severity
    );
};
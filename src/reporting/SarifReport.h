#ifndef SARIF_REPORT_H
#define SARIF_REPORT_H

#include "../security/SecurityAnalyzer.h"

#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

class SarifReportGenerator {
public:

    bool write(
        const fs::path& outputPath,
        const std::vector<SecurityIssue>& securityIssues
    ) const;

private:

    static std::string escapeJson(
        const std::string& value
    );

    static std::string severityToSarifLevel(
        Severity severity
    );
};

#endif
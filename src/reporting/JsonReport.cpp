#include "JsonReport.h"

#include <fstream>

std::string JsonReportGenerator::escapeJson(
    const std::string& value
)
{
    std::string result;

    for (const char character : value) {

        switch (character) {

        case '"':
            result += "\\\"";
            break;

        case '\\':
            result += "\\\\";
            break;

        case '\n':
            result += "\\n";
            break;

        case '\r':
            result += "\\r";
            break;

        case '\t':
            result += "\\t";
            break;

        default:
            result += character;
            break;
        }
    }

    return result;
}

std::string JsonReportGenerator::severityToString(
    Severity severity
)
{
    switch (severity) {

    case Severity::Low:
        return "LOW";

    case Severity::Medium:
        return "MEDIUM";

    case Severity::High:
        return "HIGH";

    case Severity::Critical:
        return "CRITICAL";
    }

    return "UNKNOWN";
}

bool JsonReportGenerator::write(
    const std::filesystem::path& outputPath,
    const std::filesystem::path& repositoryPath,
    const std::vector<FileInfo>& files,
    const CodeLensResult& codeResult,
    const std::vector<SecurityIssue>& securityIssues,
    const std::vector<DependencyInfo>& dependencies,
    const RiskSummary& riskSummary,
    const std::vector<Remediation>& remediations,
    const GitStatus& gitStatus
) const
{
    std::ofstream output(outputPath);

    if (!output.is_open()) {
        return false;
    }

    output << "{\n";

    // ------------------------------------------------------------
    // Repository
    // ------------------------------------------------------------

    output << "  \"repository\": \""
           << escapeJson(repositoryPath.string())
           << "\",\n";

    output << "  \"sourceFiles\": "
           << files.size()
           << ",\n";

    // ------------------------------------------------------------
    // Code Lens
    // ------------------------------------------------------------

    output << "  \"codeLens\": {\n";

    output << "    \"includes\": "
           << codeResult.includeCount
           << ",\n";

    output << "    \"functions\": "
           << codeResult.functionCount
           << ",\n";

    output << "    \"classes\": "
           << codeResult.classCount
           << ",\n";

    output << "    \"structs\": "
           << codeResult.structCount
           << "\n";

    output << "  },\n";

    // ------------------------------------------------------------
    // Risk
    // ------------------------------------------------------------

    output << "  \"risk\": {\n";

    output << "    \"level\": \""
           << escapeJson(riskSummary.level)
           << "\",\n";

    output << "    \"score\": "
           << riskSummary.score
           << ",\n";

    output << "    \"critical\": "
           << riskSummary.criticalCount
           << ",\n";

    output << "    \"high\": "
           << riskSummary.highCount
           << ",\n";

    output << "    \"medium\": "
           << riskSummary.mediumCount
           << ",\n";

    output << "    \"low\": "
           << riskSummary.lowCount
           << "\n";

    output << "  },\n";

    // ------------------------------------------------------------
    // Repository Health
    // ------------------------------------------------------------

    output << "  \"health\": {\n";

    output << "    \"sourceFiles\": "
           << files.size()
           << ",\n";

    output << "    \"dependencies\": "
           << dependencies.size()
           << ",\n";

    output << "    \"securityIssues\": "
           << securityIssues.size()
           << ",\n";

    output << "    \"riskLevel\": \""
           << escapeJson(riskSummary.level)
           << "\",\n";

    output << "    \"riskScore\": "
           << riskSummary.score
           << ",\n";

    output << "    \"critical\": "
           << riskSummary.criticalCount
           << ",\n";

    output << "    \"high\": "
           << riskSummary.highCount
           << ",\n";

    output << "    \"medium\": "
           << riskSummary.mediumCount
           << ",\n";

    output << "    \"low\": "
           << riskSummary.lowCount
           << "\n";

    output << "  },\n";

    // ------------------------------------------------------------
    // Security Issues
    // ------------------------------------------------------------

    output << "  \"securityIssues\": [\n";

    for (std::size_t i = 0;
         i < securityIssues.size();
         ++i) {

        const SecurityIssue& issue =
            securityIssues[i];

        output << "    {\n";

        output << "      \"ruleId\": \""
               << escapeJson(issue.ruleId)
               << "\",\n";

        output << "      \"title\": \""
               << escapeJson(issue.title)
               << "\",\n";

        output << "      \"severity\": \""
               << severityToString(issue.severity)
               << "\",\n";

        output << "      \"file\": \""
               << escapeJson(issue.file.string())
               << "\",\n";

        output << "      \"line\": "
               << issue.line
               << ",\n";

        output << "      \"description\": \""
               << escapeJson(issue.description)
               << "\",\n";

        if (i < remediations.size()) {

            output << "      \"recommendation\": \""
                   << escapeJson(
                          remediations[i].recommendation
                      )
                   << "\"\n";
        }
        else {

            output << "      \"recommendation\": \"\"\n";
        }

        output << "    }";

        if (i + 1 < securityIssues.size()) {
            output << ",";
        }

        output << "\n";
    }

    output << "  ],\n";

    // ------------------------------------------------------------
    // Dependencies
    // ------------------------------------------------------------

    output << "  \"dependencies\": [\n";

    for (std::size_t i = 0;
         i < dependencies.size();
         ++i) {

        const DependencyInfo& dependency =
            dependencies[i];

        output << "    {\n";

        output << "      \"name\": \""
               << escapeJson(dependency.name)
               << "\",\n";

        output << "      \"type\": \""
               << DependencyAnalyzer::typeToString(
                      dependency.type
                  )
               << "\",\n";

        output << "      \"file\": \""
               << escapeJson(dependency.file.string())
               << "\",\n";

        output << "      \"line\": "
               << dependency.line
               << "\n";

        output << "    }";

        if (i + 1 < dependencies.size()) {
            output << ",";
        }

        output << "\n";
    }

    output << "  ]\n";

        // ------------------------------------------------------------
    // Git Intelligence
    // ------------------------------------------------------------

    output << "  \"git\": {\n";

    output << "    \"isRepository\": "
           << (gitStatus.isRepository ? "true" : "false")
           << ",\n";

    output << "    \"branch\": \""
           << escapeJson(gitStatus.branch)
           << "\",\n";

    output << "    \"clean\": "
           << (gitStatus.clean ? "true" : "false")
           << ",\n";

    output << "    \"trackedFiles\": "
           << gitStatus.trackedFiles
           << ",\n";

    output << "    \"modifiedFiles\": "
           << gitStatus.modifiedFiles
           << ",\n";

    output << "    \"stagedFiles\": "
           << gitStatus.stagedFiles
           << ",\n";

    output << "    \"untrackedFiles\": "
           << gitStatus.untrackedFiles
           << ",\n";

    output << "    \"commitCount\": "
           << gitStatus.commitCount
           << ",\n";

    output << "    \"latestCommitHash\": \""
           << escapeJson(gitStatus.latestCommitHash)
           << "\",\n";

    output << "    \"latestCommitMessage\": \""
           << escapeJson(gitStatus.latestCommitMessage)
           << "\"\n";

    output << "  }\n";

    output << "}\n";

    return true;
}
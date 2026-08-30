#include "SarifReport.h"

#include <fstream>
#include <sstream>

std::string SarifReportGenerator::escapeJson(
    const std::string& value
)
{
    std::ostringstream output;

    for (char character : value) {

        switch (character) {

            case '"':
                output << "\\\"";
                break;

            case '\\':
                output << "\\\\";
                break;

            case '\n':
                output << "\\n";
                break;

            case '\r':
                output << "\\r";
                break;

            case '\t':
                output << "\\t";
                break;

            default:
                output << character;
                break;
        }
    }

    return output.str();
}

std::string SarifReportGenerator::severityToSarifLevel(
    Severity severity
)
{
    switch (severity) {

        case Severity::Critical:
        case Severity::High:
            return "error";

        case Severity::Medium:
            return "warning";

        case Severity::Low:
            return "note";
    }

    return "warning";
}

bool SarifReportGenerator::write(
    const fs::path& outputPath,
    const std::vector<SecurityIssue>& securityIssues
) const
{
    std::ofstream output(outputPath);

    if (!output.is_open()) {
        return false;
    }

    output << "{\n";

    output << "  \"version\": \"2.1.0\",\n";

    output << "  \"$schema\": "
              "\"https://json.schemastore.org/sarif-2.1.0.json\",\n";

    output << "  \"runs\": [\n";
    output << "    {\n";

    // ------------------------------------------------------------
    // Tool information
    // ------------------------------------------------------------

    output << "      \"tool\": {\n";
    output << "        \"driver\": {\n";

    output << "          \"name\": \"RepoShield\",\n";

    output << "          \"informationUri\": "
              "\"https://github.com/Danish84295/reposhield-hackathon\",\n";

    output << "          \"version\": \"1.0.0\",\n";

    output << "          \"rules\": [\n";

    for (std::size_t i = 0;
         i < securityIssues.size();
         ++i) {

        const SecurityIssue& issue =
            securityIssues[i];

        output << "            {\n";

        output << "              \"id\": \""
               << escapeJson(issue.ruleId)
               << "\",\n";

        output << "              \"name\": \""
               << escapeJson(issue.title)
               << "\",\n";

        output << "              \"shortDescription\": {\n";

        output << "                \"text\": \""
               << escapeJson(issue.title)
               << "\"\n";

        output << "              },\n";

        output << "              \"defaultConfiguration\": {\n";

        output << "                \"level\": \""
               << severityToSarifLevel(issue.severity)
               << "\"\n";

        output << "              }\n";

        output << "            }";

        if (i + 1 < securityIssues.size()) {
            output << ",";
        }

        output << "\n";
    }

    output << "          ]\n";
    output << "        }\n";
    output << "      },\n";

    // ------------------------------------------------------------
    // Results
    // ------------------------------------------------------------

    output << "      \"results\": [\n";

    for (std::size_t i = 0;
         i < securityIssues.size();
         ++i) {

        const SecurityIssue& issue =
            securityIssues[i];

        output << "        {\n";

        output << "          \"ruleId\": \""
               << escapeJson(issue.ruleId)
               << "\",\n";

        output << "          \"level\": \""
               << severityToSarifLevel(issue.severity)
               << "\",\n";

        output << "          \"message\": {\n";

        output << "            \"text\": \""
               << escapeJson(issue.description)
               << "\"\n";

        output << "          },\n";

        output << "          \"locations\": [\n";
        output << "            {\n";

        output << "              \"physicalLocation\": {\n";

        output << "                \"artifactLocation\": {\n";

        output << "                  \"uri\": \""
               << escapeJson(
                      issue.file.generic_string()
                  )
               << "\"\n";

        output << "                },\n";

        output << "                \"region\": {\n";

        output << "                  \"startLine\": "
               << issue.line
               << "\n";

        output << "                }\n";

        output << "              }\n";
        output << "            }\n";
        output << "          ]\n";

        output << "        }";

        if (i + 1 < securityIssues.size()) {
            output << ",";
        }

        output << "\n";
    }

    output << "      ]\n";

    output << "    }\n";
    output << "  ]\n";

    output << "}\n";

    return true;
}
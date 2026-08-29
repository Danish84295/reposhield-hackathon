#include "RemediationEngine.h"

#include <fstream>
#include <sstream>
#include <unordered_map>

std::string RemediationEngine::recommendationFor(
    const std::string& ruleId
)
{
    static const std::unordered_map<std::string, std::string>
        recommendations = {

        {
            "RS001",
            "Replace unsafe C string functions such as "
            "strcpy() with safer alternatives such as "
            "std::string or a bounds-checked operation."
        },

        {
            "RS002",
            "Avoid executing untrusted input through "
            "system(). Validate input and prefer a "
            "strictly controlled command interface or "
            "allowlist."
        },

        {
            "RS003",
            "Remove credentials from source code. Store "
            "secrets in environment variables or a "
            "dedicated secret-management mechanism."
        },

        {
            "RS004",
            "Replace weak cryptographic algorithms with "
            "modern, secure algorithms."
        },

        {
            "RS005",
            "Validate file paths and restrict file access "
            "to expected locations."
        },

        {
            "RS006",
            "Use parameterized queries or prepared statements "
            "instead of constructing SQL with user input."
        },

        {
            "RS007",
            "Use a cryptographically secure random generator "
            "for security-sensitive values."
        }
    };

    const auto it = recommendations.find(ruleId);

    if (it != recommendations.end()) {
        return it->second;
    }

    return "Review this security finding and apply "
           "appropriate defensive coding practices.";
}

std::vector<Remediation> RemediationEngine::generate(
    const std::vector<SecurityIssue>& issues
) const
{
    std::vector<Remediation> remediations;

    for (const SecurityIssue& issue : issues) {
        remediations.push_back({
            issue.ruleId,
            recommendationFor(issue.ruleId)
        });
    }

    return remediations;
}

std::vector<FixResult> RemediationEngine::fix(
    const std::vector<SecurityIssue>& issues,
    bool dryRun
) const
{
    std::vector<FixResult> results;

    for (const SecurityIssue& issue : issues) {
        results.push_back(
            fixIssue(issue, dryRun)
        );
    }

    return results;
}

FixResult RemediationEngine::fixIssue(
    const SecurityIssue& issue,
    bool dryRun
) const
{
    if (issue.ruleId == "RS001") {
        return fixUnsafeCString(issue, dryRun);
    }

    FixResult result;

    result.ruleId = issue.ruleId;
    result.file = issue.file;
    result.line = issue.line;
    result.applied = false;

    result.message =
        "Automatic fix is not available for this rule. "
        "Manual remediation is required.";

    return result;
}

FixResult RemediationEngine::fixUnsafeCString(
    const SecurityIssue& issue,
    bool dryRun
) const
{
    FixResult result;

    result.ruleId = issue.ruleId;
    result.file = issue.file;
    result.line = issue.line;
    result.applied = false;

    // --------------------------------------------------
    // Read source file
    // --------------------------------------------------

    std::ifstream input(issue.file);

    if (!input) {
        result.message = "Unable to open source file.";
        return result;
    }

    std::ostringstream buffer;
    buffer << input.rdbuf();

    const std::string content = buffer.str();

    std::istringstream lines(content);

    std::vector<std::string> sourceLines;
    std::string line;

    while (std::getline(lines, line)) {
        sourceLines.push_back(line);
    }

    // --------------------------------------------------
    // Validate reported vulnerability line
    // --------------------------------------------------

    if (
        issue.line == 0 ||
        issue.line > sourceLines.size()
    ) {
        result.message = "Invalid vulnerability line.";
        return result;
    }

    std::string& targetLine =
        sourceLines[issue.line - 1];

    // --------------------------------------------------
    // Find strcpy()
    // --------------------------------------------------

    const std::string search = "strcpy(";

    const std::size_t position =
        targetLine.find(search);

    if (position == std::string::npos) {
        result.message =
            "strcpy() was not found at the reported line.";

        return result;
    }

    // --------------------------------------------------
    // Parse strcpy(destination, source)
    // --------------------------------------------------

    const std::size_t open =
        position + search.length();

    const std::size_t comma =
        targetLine.find(',', open);

    const std::size_t close =
        targetLine.find(')', open);

    if (
        comma == std::string::npos ||
        close == std::string::npos ||
        comma > close
    ) {
        result.message =
            "Unable to safely parse strcpy() arguments.";

        return result;
    }

    std::string destination =
        targetLine.substr(
            open,
            comma - open
        );

    std::string source =
        targetLine.substr(
            comma + 1,
            close - comma - 1
        );

    // --------------------------------------------------
    // Trim whitespace
    // --------------------------------------------------

    const auto trim = [](std::string value) {

        const std::size_t first =
            value.find_first_not_of(" \t");

        const std::size_t last =
            value.find_last_not_of(" \t");

        if (
            first == std::string::npos ||
            last == std::string::npos
        ) {
            return std::string();
        }

        return value.substr(
            first,
            last - first + 1
        );
    };

    destination = trim(destination);
    source = trim(source);

    if (
        destination.empty() ||
        source.empty()
    ) {
        result.message =
            "Unable to determine strcpy() arguments.";

        return result;
    }

    // --------------------------------------------------
    // Verify destination is a character array
    // --------------------------------------------------

    const std::string declaration =
        "char " + destination + "[";

    bool destinationIsArray = false;

    for (const std::string& sourceLine : sourceLines) {

        if (
            sourceLine.find(declaration)
            != std::string::npos
        ) {
            destinationIsArray = true;
            break;
        }
    }

    if (!destinationIsArray) {

        result.message =
            "Automatic fix refused: destination '" +
            destination +
            "' is not verified as a local character array.";

        if (dryRun) {
            result.message =
                "[DRY RUN] " + result.message;
        }

        return result;
    }

    // --------------------------------------------------
    // Preserve indentation
    // --------------------------------------------------

    const std::size_t firstNonWhitespace =
        targetLine.find_first_not_of(" \t");

    const std::string indentation =
        firstNonWhitespace == std::string::npos
            ? ""
            : targetLine.substr(
                  0,
                  firstNonWhitespace
              );

    // --------------------------------------------------
    // Build safe replacement
    // --------------------------------------------------

    const std::string replacement =
        indentation +
        "std::strncpy(" +
        destination +
        ", " +
        source +
        ", sizeof(" +
        destination +
        ") - 1);";

    const std::string nullTerminate =
        indentation +
        destination +
        "[sizeof(" +
        destination +
        ") - 1] = '\\0';";

    // --------------------------------------------------
    // Dry run
    // --------------------------------------------------

    if (dryRun) {

        result.message =
            "[DRY RUN] Safe fix available: replace "
            "strcpy(" +
            destination +
            ", " +
            source +
            ") with a bounds-checked copy.";

        result.applied = false;

        return result;
    }

    // --------------------------------------------------
    // Apply modification
    // --------------------------------------------------

    targetLine = replacement;

    sourceLines.insert(
        sourceLines.begin() + issue.line,
        nullTerminate
    );

    // --------------------------------------------------
    // Write complete source file
    // --------------------------------------------------

    std::ofstream output(issue.file);

    if (!output) {
        result.message =
            "Unable to write modified source file.";

        return result;
    }

    // IMPORTANT:
    // Only ONE loop is required here.
    // Each source line is written exactly once.

    for (const std::string& sourceLine : sourceLines) {
        output << sourceLine << '\n';
    }

    output.close();

    if (!output) {
        result.message =
            "Failed while writing modified source file.";

        return result;
    }

    result.applied = true;

    result.message =
        "Automatically replaced strcpy() with a "
        "bounds-checked std::strncpy() operation.";

    return result;
}
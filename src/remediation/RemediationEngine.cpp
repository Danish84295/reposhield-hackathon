#include "RemediationEngine.h"

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
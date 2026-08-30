#ifndef REPOSHIELD_CONFIG_H
#define REPOSHIELD_CONFIG_H

#include "../security/SecurityAnalyzer.h"

#include <filesystem>
#include <set>
#include <string>
#include <vector>

namespace fs = std::filesystem;

class SecurityConfig {
public:

    SecurityConfig();

    bool load(const fs::path& repositoryPath);

    bool shouldFail(const std::vector<SecurityIssue>& issues) const;

    bool isConfigured() const;

    std::string getPolicyPath() const;

private:

    std::set<Severity> failOn;

    bool configured;

    fs::path policyPath;

    static bool parseSeverity(
        const std::string& value,
        Severity& severity
    );

    static std::string trim(
        const std::string& value
    );
};

#endif
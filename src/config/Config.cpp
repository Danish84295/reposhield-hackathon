#include "Config.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

SecurityConfig::SecurityConfig()
    : configured(false)
{
    // Default policy:
    // Critical and High findings fail the security gate.
    failOn.insert(Severity::Critical);
    failOn.insert(Severity::High);
}

std::string SecurityConfig::trim(
    const std::string& value
)
{
    std::size_t start = 0;
    std::size_t end = value.size();

    while (start < end &&
           std::isspace(
               static_cast<unsigned char>(value[start])
           )) {
        ++start;
    }

    while (end > start &&
           std::isspace(
               static_cast<unsigned char>(value[end - 1])
           )) {
        --end;
    }

    return value.substr(start, end - start);
}

bool SecurityConfig::parseSeverity(
    const std::string& value,
    Severity& severity
)
{
    std::string normalized = trim(value);

    std::transform(
        normalized.begin(),
        normalized.end(),
        normalized.begin(),
        [](unsigned char character) {
            return static_cast<char>(
                std::toupper(character)
            );
        }
    );

    if (normalized == "CRITICAL") {
        severity = Severity::Critical;
        return true;
    }

    if (normalized == "HIGH") {
        severity = Severity::High;
        return true;
    }

    if (normalized == "MEDIUM") {
        severity = Severity::Medium;
        return true;
    }

    if (normalized == "LOW") {
        severity = Severity::Low;
        return true;
    }

    return false;
}

bool SecurityConfig::load(
    const fs::path& repositoryPath
)
{
    configured = false;

    policyPath = repositoryPath / ".reposhield.yml";

    std::ifstream input(policyPath);

    if (!input.is_open()) {
        // No configuration file.
        // Keep the default policy.
        return true;
    }

    std::set<Severity> configuredLevels;

    std::string line;
    bool insideSecurity = false;
    bool insideFailOn = false;

    while (std::getline(input, line)) {

        // Remove comments.
        const std::size_t commentPosition =
            line.find('#');

        if (commentPosition != std::string::npos) {
            line = line.substr(0, commentPosition);
        }

        line = trim(line);

        if (line.empty()) {
            continue;
        }

        if (line == "security:") {
            insideSecurity = true;
            insideFailOn = false;
            continue;
        }

        if (!insideSecurity) {
            continue;
        }

        if (line == "fail_on:") {
            insideFailOn = true;
            continue;
        }

        if (insideFailOn &&
            line.size() >= 2 &&
            line[0] == '-') {

            std::string severityText =
                trim(line.substr(1));

            Severity severity;

            if (parseSeverity(
                    severityText,
                    severity)) {

                configuredLevels.insert(severity);
            }

            continue;
        }

        // A new top-level key ends the fail_on section.
        if (!line.empty() &&
            line.back() == ':') {

            insideFailOn = false;
        }
    }

    if (!configuredLevels.empty()) {

        failOn = configuredLevels;
        configured = true;

        return true;
    }

    // Configuration file exists but contains no
    // valid fail_on severity. Keep defaults.
    return false;
}

bool SecurityConfig::shouldFail(
    const std::vector<SecurityIssue>& issues
) const
{
    for (const SecurityIssue& issue : issues) {

        if (failOn.find(issue.severity) !=
            failOn.end()) {

            return true;
        }
    }

    return false;
}

bool SecurityConfig::isConfigured() const
{
    return configured;
}

std::string SecurityConfig::getPolicyPath() const
{
    return policyPath.string();
}
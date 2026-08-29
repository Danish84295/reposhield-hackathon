#include "GitAnalyzer.h"

#include <cstdio>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#endif

std::string GitAnalyzer::trim(
    const std::string& value
)
{
    const std::size_t first =
        value.find_first_not_of(" \t\r\n");

    const std::size_t last =
        value.find_last_not_of(" \t\r\n");

    if (
        first == std::string::npos ||
        last == std::string::npos
    ) {
        return "";
    }

    return value.substr(
        first,
        last - first + 1
    );
}

std::string GitAnalyzer::runCommand(
    const fs::path& repositoryPath,
    const std::string& command
)
{
    /*
        Git Intelligence intentionally uses the Git CLI
        instead of libgit2 or another third-party library.

        This keeps RepoShield dependency-free at the C++
        library level.
    */

    std::string path =
        fs::absolute(repositoryPath).string();

#ifdef _WIN32
    /*
        Convert Windows separators to forward slashes.
        Git accepts these paths correctly.
    */
    for (char& character : path) {
        if (character == '\\') {
            character = '/';
        }
    }

    const std::string gitCommand =
        "git -C \"" +
        path +
        "\" " +
        command +
        " 2>nul";
#else
    const std::string gitCommand =
        "git -C \"" +
        path +
        "\" " +
        command +
        " 2>/dev/null";
#endif

    FILE* pipe = popen(
        gitCommand.c_str(),
        "r"
    );

    if (!pipe) {
        return "";
    }

    std::string result;
    char buffer[256];

    while (fgets(
        buffer,
        sizeof(buffer),
        pipe
    ) != nullptr) {

        result += buffer;
    }

    pclose(pipe);

    return trim(result);
}

GitStatus GitAnalyzer::analyze(
    const fs::path& repositoryPath
) const
{
    GitStatus status;

    const std::string repositoryCheck =
        runCommand(
            repositoryPath,
            "rev-parse --is-inside-work-tree"
        );

    if (repositoryCheck != "true") {
        return status;
    }

    status.isRepository = true;

    status.branch =
        runCommand(
            repositoryPath,
            "branch --show-current"
        );

    if (status.branch.empty()) {
        status.branch = "DETACHED HEAD";
    }

    const std::string porcelain =
        runCommand(
            repositoryPath,
            "status --porcelain"
        );

    if (!porcelain.empty()) {
        status.clean = false;
    }

    std::istringstream statusLines(
        porcelain
    );

    std::string line;

    while (std::getline(
        statusLines,
        line
    )) {

        if (line.size() < 2) {
            continue;
        }

        const char indexStatus = line[0];
        const char workTreeStatus = line[1];

        if (
            indexStatus == '?' &&
            workTreeStatus == '?'
        ) {
            ++status.untrackedFiles;
            continue;
        }

        if (indexStatus != ' ') {
            ++status.stagedFiles;
        }

        if (workTreeStatus != ' ') {
            ++status.modifiedFiles;
        }
    }

    const std::string tracked =
        runCommand(
            repositoryPath,
            "ls-files"
        );

    if (!tracked.empty()) {

        std::istringstream trackedLines(
            tracked
        );

        while (std::getline(
            trackedLines,
            line
        )) {
            if (!line.empty()) {
                ++status.trackedFiles;
            }
        }
    }

    const std::string commits =
        runCommand(
            repositoryPath,
            "rev-list --count HEAD"
        );

    if (!commits.empty()) {

        try {
            status.commitCount =
                std::stoi(commits);
        }
        catch (...) {
            status.commitCount = 0;
        }
    }

    const std::string latestCommit =
        runCommand(
            repositoryPath,
            "log -1 --format=%h%n%s"
        );

    if (!latestCommit.empty()) {

        std::istringstream commitLines(
            latestCommit
        );

        std::getline(
            commitLines,
            status.latestCommitHash
        );

        std::getline(
            commitLines,
            status.latestCommitMessage
        );

        status.latestCommitHash =
            trim(status.latestCommitHash);

        status.latestCommitMessage =
            trim(status.latestCommitMessage);
    }

    return status;
}

void GitAnalyzer::print(
    const GitStatus& status
) const
{
    std::cout
        << "----------------------------------------\n"
        << "           GIT INTELLIGENCE\n"
        << "----------------------------------------\n\n";

    if (!status.isRepository) {

        std::cout
            << "Git repository: NO\n\n"
            << "This directory is not a Git repository.\n";

        return;
    }

    std::cout
        << "Git repository: YES\n\n";

    std::cout
        << "Branch:          "
        << status.branch
        << "\n";

    std::cout
        << "Working tree:    "
        << (status.clean ? "CLEAN" : "MODIFIED")
        << "\n";

    std::cout
        << "Tracked files:   "
        << status.trackedFiles
        << "\n";

    std::cout
        << "Modified files:  "
        << status.modifiedFiles
        << "\n";

    std::cout
        << "Staged files:    "
        << status.stagedFiles
        << "\n";

    std::cout
        << "Untracked files: "
        << status.untrackedFiles
        << "\n";

    std::cout
        << "Commits:         "
        << status.commitCount
        << "\n\n";

    if (!status.latestCommitHash.empty()) {

        std::cout
            << "LATEST COMMIT\n\n";

        std::cout
            << "  Hash:    "
            << status.latestCommitHash
            << "\n";

        std::cout
            << "  Message: "
            << status.latestCommitMessage
            << "\n";
    }

    std::cout << "\n";
}

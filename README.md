# RepoShield

> A standalone C++17 developer CLI for repository security, health, and risk analysis.

RepoShield analyzes a local software repository and produces a developer-focused report covering:

- Repository statistics
- Code structure
- Security vulnerabilities
- Risk scoring
- Dependency analysis
- Dependency graph
- Git repository intelligence
- Remediation guidance
- JSON reports
- SARIF reports
- Security policy enforcement

Built using the **C++17 standard library only**.


## Why RepoShield?
Developers often need multiple tools to understand the health and security of a repository.

RepoShield brings several useful checks into a single CLI command.

```
Repository
     |
     v
 RepoShield
     |
     +-----------------------------+
     |                             |
     v                             v
Repository Statistics          Code Lens
Security Analysis             Dependency Analysis
Risk Scoring                  Git Intelligence
Remediation Guidance          Security Policy
     |                             |
     +-------------+---------------+
                   |
                   v
          Terminal / JSON / SARIF
```

## Features

### Repository Statistics

RepoShield scans the repository and reports:

Total files
Source files
Header files
Total repository size
Total lines
Detected programming languages

Example:
```
Files:          14
Source files:   14
Header files:   0
Total size:     8391 bytes
Total lines:    344

LANGUAGES

JavaScript  14 files (100%), 344 lines
```
---

### Code Lens

Code Lens provides a lightweight structural view of the codebase.

It detects:

- Include count
- Functions
- Classes
- Structs
- Function locations
- Function sizes

Example:
```
FUNCTIONS

  process
    File: vulnerable.cpp
    Line: 15
    Lines: 3

  calculate
    File: vulnerable.cpp
    Line: 19
    Lines: 7

  unsafeCopy
    File: vulnerable.cpp
    Line: 28
    Lines: 5
```
---

### Security Analysis

RepoShield detects common security-related source-code patterns.

Current security rules:

```
| Rule  | Finding                              | Severity |
| ----- | ------------------------------------ | -------- |
| RS001 | Unsafe C string function             | HIGH     |
| RS002 | Command execution                    | HIGH     |
| RS003 | Possible hardcoded secret            | CRITICAL |
| RS004 | Weak cryptographic algorithm         | HIGH     |
| RS005 | Potentially dangerous file operation | MEDIUM   |
| RS006 | Potential SQL injection              | HIGH     |
| RS007 | Insecure random number generation    | MEDIUM   |
```

Each security finding contains:

- Rule ID
- Title
- Severity
- File
- Line number
- Description
- Remediation recommendation

Example:

```
[RS003] Possible hardcoded secret
  Severity: CRITICAL
  File: vulnerable.cpp
  Line: 41

  A credential-like value appears to be stored
  directly in source code.
```

---
### Risk Scoring

RepoShield calculates a repository risk score from:

0 → 100

and reports a corresponding risk level:
```
SAFE
LOW
MEDIUM
HIGH
CRITICAL
```

Example:
```
RISK SUMMARY

Risk Level: CRITICAL
Risk Score: 100 / 100

Critical: 1
High:     4
Medium:   2
Low:      0
```

---
### Supply Chain Analysis

RepoShield detects source-level dependencies from repository files.

Dependencies are classified as:

- Standard library dependencies
- External dependencies

Example:

```
SUPPLY CHAIN

Dependencies found: 6

[STANDARD] cstring
[STANDARD] cstdlib
[STANDARD] iostream
[STANDARD] cstdio
[STANDARD] string
[EXTERNAL] openssl/sha.h
```

Each dependency can contain:

- Name
- Type
- Risk
- Risk reason
- Source file
- Line number

---
### Dependency Graph

RepoShield displays relationships between source files and detected dependencies.

Example:
```
vulnerable.cpp
  +-- [STANDARD] cstring
  +-- [STANDARD] cstdlib
  +-- [STANDARD] iostream
  +-- [STANDARD] cstdio
  +-- [STANDARD] string
  +-- [EXTERNAL] openssl/sha.h
```

This provides a simple way to understand the dependency structure of a repository.


---
### Git Intelligence

When analyzing a Git repository, RepoShield can report:

- Repository status
- Current branch
- Clean / dirty state
- Tracked files
- Modified files
- Staged files
- Untracked files
- Commit count
- Latest commit hash
- Latest commit message
It is done by 
```
./reposhield git ./my-project
```

Example:
```
GIT

Repository: Git repository
Branch: main
Clean: true
Tracked files: 24
Modified files: 0
Staged files: 0
Untracked files: 0
Commit count: 18
```
Git is optional. RepoShield can still analyze repositories that are not Git repositories.

---

### Remediation Guidance

RepoShield provides actionable remediation guidance for detected security findings.

For each finding, RepoShield reports:

- Rule ID
- File
- Line number
- Recommendation

Example:

```text
[RS001] Unsafe C string function
  File: demo-target\vulnerable.cpp
  Line: 30
  Recommendation:
    Replace unsafe C string functions such as strcpy()
    with safer alternatives such as std::string or a
    bounds-checked operation.
```
### Automatic Remediation

RepoShield currently supports automatic remediation for RS001 — Unsafe C string function.

The fix command can automatically replace the detected unsafe strcpy() usage with a safer implementation.

Run:
```
./reposhield fix demo-target
```
To preview the changes without modifying the repository:
```
./reposhield fix demo-target --dry-run
```
After applying the fix, run the analysis again to verify the result:
```
./reposhield analyze demo-target
```
If the remediation was successful, the RS001 finding should no longer appear.

- Note: Automatic remediation is currently implemented for RS001 only. Other security rules provide remediation guidance but are not automatically modified.

This provides a complete workflow:

#### Detect → Fix → Verify

```
./reposhield analyze demo-target
        ↓
      RS001
        ↓
./reposhield fix demo-target
        ↓
   RS001 fixed
        ↓
./reposhield analyze demo-target
        ↓
   RS001 removed
```
---
### JSON Reports

RepoShield can generate a structured JSON report.
```
./reposhield analyze ./my-project --json report.json
```

The JSON report contains information such as:

- Repository information
- Repository health
- Code statistics
- Security findings
- Risk score
- Dependencies
- Dependency risks
- Git information
- Remediation recommendations

---
### SARIF Reports

RepoShield can generate a SARIF security report.
```
./reposhield analyze ./my-project --sarif report.sarif
```

SARIF provides a standardized machine-readable format for security-analysis results and can be consumed by compatible development and security tooling.

---
### Security Policy Enforcement

RepoShield can fail an analysis when configured security findings match the configured policy.

Example:
```
----------------------------------------
        SECURITY POLICY FAILED
----------------------------------------

One or more findings match the configured
fail_on policy.
```

This allows RepoShield to be used as part of developer workflows and CI checks.


## Installation

RepoShield is designed as a standalone C++17 executable.

### Requirements
- C++17-compatible compiler
- Standard C++ library
- Git (optional, for Git intelligence)

No third-party C++ libraries are required.

### Clone the Repository

Clone RepoShield from GitHub:

```bash
git clone https://github.com/Danish84295/reposhield-hackathon.git
cd reposhield-hackathon
```

## Build
From the repository root:

```
g++ -std=c++17 \
src/main.cpp \
src/core/FileScanner.cpp \
src/core/RepositoryStats.cpp \
src/codelens/CodeLens.cpp \
src/security/SecurityAnalyzer.cpp \
src/supplychain/DependencyAnalyzer.cpp \
src/graph/DependencyGraph.cpp \
src/risk/RiskScorer.cpp \
src/remediation/RemediationEngine.cpp \
src/reporting/HealthReport.cpp \
src/reporting/JsonReport.cpp \
src/reporting/SarifReport.cpp \
src/git/GitAnalyzer.cpp \
src/config/Config.cpp \
-I src \
-o reposhield
```


After building:
```
./reposhield
```

## Usage

### Help

RepoShield provides global and command-specific help.

#### Global Help

```bash
./reposhield --help
```
or
```
./reposhield -h
```
Output:
```
RepoShield - Zero-Dependency Repository Intelligence

Usage:
  reposhield <command> <path> [options]

Commands:
  analyze    Analyze repository security, health, and dependencies
  fix        Apply supported automatic remediation
  git        Show Git repository intelligence

General options:
  --help, -h           Show help information

Exit codes:
  0                    Success
  1                    Error or security policy violation

Run 'reposhield <command> --help' for command-specific help.
```

### Analyze Help
```
./reposhield analyze --help
```
Output:
```
RepoShield - Analyze

Usage:
  reposhield analyze <path> [options]

Description:
  Analyze repository structure, security, dependencies,
  risk, Git information, and repository health.

Options:
  --json <file>       Generate a JSON report
  --sarif <file>      Generate a SARIF report
  --help, -h          Show this help message
```

### Fix Help
```
./reposhield fix --help
```
Output:
```
RepoShield - Fix

Usage:
  reposhield fix <path> [options]

Description:
  Apply supported automatic security remediation.

Options:
  --dry-run           Preview changes without modifying files
  --help, -h          Show this help message
```

### Git Help
```
./reposhield git --help
```
Output:
```
RepoShield - Git

Usage:
  reposhield git <path>

Description:
  Display Git repository intelligence.

Options:
  --help, -h          Show this help message
```

### Analyze a Repository
Analyze a local repository:
```
./reposhield analyze ./my-project
```

###  Generate JSON
Generate a machine-readable JSON report:
```
./reposhield analyze ./my-project --json report.json
```

###  Generate SARIF
Generate a SARIF security report:
```
./reposhield analyze ./my-project --sarif report.sarif
```

###  Generate JSON and SARIF
Generate both report formats:
```
./reposhield analyze ./my-project \
    --json report.json \
    --sarif report.sarif
```
## Exit Codes

RepoShield uses meaningful exit codes so it can be used in developer workflows and CI environments.

| Exit Code | Meaning |
| --------- | ------- |
| `0` | Analysis completed successfully and no configured security policy was violated |
| `1` | Analysis failed, an invalid configuration was detected, or the security policy was violated |

For example:

```bash
./reposhield analyze demo-target
echo $?
```
If the repository violates the configured security policy, RepoShield exits with:
```
1
```
This allows scripts and CI systems to detect security policy failures automatically.

### CI Security Gate

RepoShield can act as a security gate in automated workflows:

```
Repository
    ↓
RepoShield analyze
    ↓
Security Analysis
    ↓
Policy Evaluation
    ↓
PASS → Exit Code 0
FAIL → Exit Code 1
```
This means a security policy violation can cause an automated workflow to fail without requiring a separate security-scanning dependency.

## Arbitrary Repository Analysis

RepoShield is not tied to the included demo repository.
It accepts arbitrary local repository paths.


For example:
```
./reposhield analyze ../research-paper-ai
```
or:
```
./reposhield analyze ../wexaai-Assessment-smart-mess-tracker
```
This allows the same executable to analyze different projects without changing the source code.

Example result:
```
Repository: ../research-paper-ai

Source files: 14

...

SECURITY

Issues found: 0

No security issues detected.

...

Risk Level: SAFE
Risk Score: 0 / 100
```

## Example: Vulnerable Repository

For a repository containing intentionally vulnerable code:
```
----------------------------------------
              SECURITY
----------------------------------------

Issues found: 7

[RS001] Unsafe C string function
  Severity: HIGH
  File: vulnerable.cpp
  Line: 30

[RS002] Command execution detected
  Severity: HIGH
  File: vulnerable.cpp
  Line: 35

[RS003] Possible hardcoded secret
  Severity: CRITICAL
  File: vulnerable.cpp
  Line: 41

[RS004] Weak cryptographic algorithm
  Severity: HIGH
  File: vulnerable.cpp
  Line: 44

[RS005] Potentially dangerous file operation
  Severity: MEDIUM
  File: vulnerable.cpp
  Line: 47

[RS006] Potential SQL injection
  Severity: HIGH
  File: vulnerable.cpp
  Line: 52

[RS007] Insecure random number generation
  Severity: MEDIUM
  File: vulnerable.cpp
  Line: 55
```

Risk summary:
```
Risk Level: CRITICAL
Risk Score: 100 / 100

Critical: 1
High:     4
Medium:   2
Low:      0
```

## Output Formats

RepoShield provides three primary output forms.

### Terminal

Human-readable output designed for developers working directly from the command line.

### JSON

Machine-readable repository analysis suitable for further processing.

### SARIF

Standardized security-analysis output for compatible security and development tooling.

```
                    RepoShield
                        |
             +----------+----------+
             |          |          |
             v          v          v
          Terminal     JSON      SARIF
```


## Architecture

RepoShield follows a modular C++ architecture.
```

                    +----------------+
                    |      CLI       |
                    |   main.cpp     |
                    +-------+--------+
                            |
                            v
                  +-------------------+
                  |   File Scanner     |
                  +---------+---------+
                            |
             +--------------+--------------+
             |              |              |
             v              v              v
      +-------------+ +-------------+ +-------------+
      | Repository  | |  Code Lens  | |  Security   |
      | Statistics  | |             | |  Analyzer   |
      +------+------+ +------+------+ +------+------+
             |               |               |
             +---------------+---------------+
                             |
                             v
                    +----------------+
                    |  Risk Scoring  |
                    +-------+--------+
                            |
              +-------------+-------------+
              |             |             |
              v             v             v
       +-------------+ +---------+ +-------------+
       | Supply Chain| |   Git   | | Remediation |
       |   Analysis  | | Analyzer| |   Engine    |
       +------+------+ +----+----+ +------+------+
              |             |             |
              +-------------+-------------+
                            |
                            v
                    +----------------+
                    |    Reporting   |
                    +-------+--------+
                            |
              +-------------+-------------+
              |             |             |
              v             v             v
         +---------+    +--------+    +--------+
         |Terminal |    |  JSON  |    | SARIF  |
         +---------+    +--------+    +--------+
```

## Project Structure
```
reposhield/
|
├── src/
│   ├── main.cpp
│   ├── cli/
│   ├── core/
│   ├── codelens/
│   ├── security/
│   ├── supplychain/
│   ├── graph/
│   ├── risk/
│   ├── remediation/
│   ├── reporting/
│   ├── git/
│   └── config/
|
├── tests/
├── demo-target/
├── docs/
├── README.md
├── STDLIB.md
└── LICENSE
```

## Design Principles

RepoShield is designed around the requirements of the Developer Tools & CLI track.

### Standalone

RepoShield builds into a single runnable executable.

### CLI First

The primary interface is a clean command-line interface.

### Standard Library

Core repository analysis is implemented using the C++17 standard library.

### Developer Focused

Output is designed to be useful directly from a developer terminal.

### Machine Readable

JSON and SARIF outputs allow analysis results to be consumed by other tools.

### Meaningful Exit Status

Security policy failures can produce a failed analysis status, making RepoShield suitable for automated workflows.

### Modular Architecture

Analysis responsibilities are separated into focused components.


## Demo Flow
```
1. Build RepoShield
        |
        v
2. Analyze vulnerable demo repository
        |
        v
3. Show security findings
        |
        v
4. Show risk score
        |
        v
5. Show dependency analysis
        |
        v
6. Show remediation guidance
        |
        v
7. Generate JSON + SARIF
        |
        v
8. Analyze a completely different repository
        |
        v
9. Show that RepoShield works with
   arbitrary local repository paths
```
This demonstrates both the security-analysis capabilities and the general-purpose CLI workflow.


## Limitations

RepoShield currently analyzes repositories available on the local filesystem.

It does not directly download remote repositories.

For a remote repository, clone it first and then provide its local path to RepoShield

Example:
```
git clone <repository-url>

./reposhield analyze ./repository
```

## Standard Library Compliance

RepoShield's core repository analysis is implemented using the C++17 standard library.
No third-party C++ libraries are required for repository scanning, code analysis,risk scoring, dependency analysis, or report generation.

Examples include:

- std::filesystem for repository traversal
- std::string for text processing
- std::vector for collections
- std::map / standard containers for analysis data
- std::fstream for report generation
- Standard process/system interfaces for Git integration

For detailed information about the standard-library implementation and Track A compliance, see:

**[STDLIB.md](STDLIB.md)**

## License

See [LICENSE](LICENSE).
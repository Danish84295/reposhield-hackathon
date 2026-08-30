# RepoShield — Standard Library Compliance

RepoShield is implemented as a standalone C++17 developer CLI using the **C++17 standard library** for its core functionality.

No third-party C++ libraries are required for repository scanning, code analysis, security analysis, risk scoring, dependency analysis, remediation, or report generation.

## C++ Standard

RepoShield requires a **C++17-compatible compiler**.

The project is compiled using:

```bash
g++ -std=c++17
```

## Standard Library Components Used

### std::filesystem

Used for:
- Repository traversal
- Directory scanning
- File discovery
- File path handling
- File metadata

Example:
```
std::filesystem::recursive_directory_iterator
std::filesystem::path
```

### std::string

Used for:

- Source-code text processing
- Command-line arguments
- Security pattern detection
- Report generation
- Git output processing

### std::vector

Used for:

- Collections of source files
- Security findings
- Functions
- Dependencies
- Analysis results

### std::map

Used for:

- Analysis data
- Language statistics
- Risk information
- Structured result storage
- std::fstream

Used for:

- Reading source files
- Writing JSON reports
- Writing SARIF reports

## Standard Algorithms

RepoShield uses standard C++ algorithms where appropriate for processing analysis data.

Examples include:
```
std::find
std::sort
std::count
```

### Standard Streams

Standard C++ streams are used for CLI input and output.

Examples:
```
std::cout
std::cerr
std::ifstream
std::ofstream
```

## Git Integration

Git intelligence is implemented without a third-party Git library.

RepoShield invokes Git through standard system/process interfaces and analyzes the returned information.

Git is optional.

If the target repository is not a Git repository, RepoShield can still perform repository analysis.

## JSON and SARIF Generation

JSON and SARIF reports are generated directly by RepoShield.

No third-party JSON or SARIF library is required.

The reporting components construct the required output using standard C++ strings, streams, containers, and file operations.

## Dependency Analysis

RepoShield performs source-level dependency analysis using its own C++ implementation.

It detects dependencies from source files and classifies them as:

- Standard library dependencies
- External dependencies

No external dependency-analysis library is required.

## Security Analysis

Security rules are implemented directly inside RepoShield.

The analyzer examines source-code text and detects supported security patterns such as:

- Unsafe C string functions
- Command execution
- Possible hardcoded secrets
- Weak cryptographic algorithms
- Potentially dangerous file operations
- Potential SQL injection
- Insecure random number generation

No third-party security-scanning library is required.

## Automatic Remediation

Automatic remediation is implemented directly in RepoShield.

Currently, automatic remediation is supported for:
```
RS001 — Unsafe C string function
```
The remediation logic uses standard C++ file and string-processing facilities.

## Third-Party Libraries

RepoShield does not require third-party C++ libraries for its core implementation.

The project is designed to build as a standalone executable.


## Build Dependencies

The basic requirements are:

- C++17-compatible compiler
- Standard C++ library
- Git (optional, for Git intelligence)

Example build command:

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
```markdown

## Compliance Summary
| Requirement               | RepoShield                           |
| ------------------------- | ------------------------------------ |
| C++17                     | Yes                                  |
| Standard library based    | Yes                                  |
| Third-party C++ libraries | None required                        |
| Repository scanning       | `std::filesystem`                    |
| File processing           | Standard C++ streams                 |
| Text processing           | `std::string`                        |
| Collections               | Standard containers                  |
| JSON generation           | Built-in implementation              |
| SARIF generation          | Built-in implementation              |
| Security analysis         | Built-in implementation              |
| Risk scoring              | Built-in implementation              |
| Dependency analysis       | Built-in implementation              |
| Automatic remediation     | Built-in implementation              |
| Git integration           | Git CLI + standard system interfaces |
```

## Conclusion
RepoShield is designed to satisfy the Developer Tools & CLI requirement of using the C++17 standard library for its core implementation.

The project does not depend on helper packages or third-party C++ libraries for its primary repository-analysis functionality.

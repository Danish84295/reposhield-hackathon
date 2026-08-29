#include "CodeLens.h"

#include <fstream>
#include <iterator>
#include <regex>
#include <string>

std::string CodeLens::readFile(
    const fs::path& path
) const
{
    std::ifstream file(path);

    if (!file) {
        return {};
    }

    return std::string(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

CodeLensResult CodeLens::analyze(
    const std::vector<FileInfo>& files
) const
{
    CodeLensResult result;

    for (const FileInfo& file : files) {

        const std::string content =
            readFile(file.path);

        if (content.empty()) {
            continue;
        }

        result.includeCount +=
            countIncludes(content);

        const std::vector<FunctionInfo> functions =
            detectFunctions(content, file.path);

        const std::vector<ClassInfo> classes =
            detectClasses(content, file.path);

        const std::vector<StructInfo> structs =
            detectStructs(content, file.path);

        result.functions.insert(
            result.functions.end(),
            functions.begin(),
            functions.end()
        );

        result.classes.insert(
            result.classes.end(),
            classes.begin(),
            classes.end()
        );

        result.structs.insert(
            result.structs.end(),
            structs.begin(),
            structs.end()
        );
    }

    result.functionCount = result.functions.size();
    result.classCount = result.classes.size();
    result.structCount = result.structs.size();

    return result;
}

std::size_t CodeLens::countIncludes(
    const std::string& content
) const
{
    const std::regex pattern(
        R"(#\s*include\s*[<"][^>"]+[>"])"
    );

    std::size_t count = 0;

    std::sregex_iterator begin(
        content.begin(),
        content.end(),
        pattern
    );

    const std::sregex_iterator end;

    for (auto it = begin; it != end; ++it) {
        ++count;
    }

    return count;
}

std::vector<FunctionInfo> CodeLens::detectFunctions(
    const std::string& content,
    const fs::path& file
) const
{
    std::vector<FunctionInfo> functions;

    const std::regex pattern(
        R"(^\s*(?:(?:static|inline|virtual|explicit|constexpr|const|extern)\s+)*(?:[A-Za-z_][A-Za-z0-9_:<>*&]*\s+)+([A-Za-z_][A-Za-z0-9_:]*)\s*\([^;{}]*\)\s*(?:const\s*)?\{)"
    );

    std::size_t lineStart = 0;
    std::size_t currentLine = 1;

    while (lineStart < content.size()) {

        const std::size_t lineEnd =
            content.find('\n', lineStart);

        const std::size_t actualEnd =
            lineEnd == std::string::npos
                ? content.size()
                : lineEnd;

        const std::string line =
            content.substr(
                lineStart,
                actualEnd - lineStart
            );

        std::smatch match;

        if (std::regex_search(line, match, pattern)) {

            if (match.size() >= 2) {

                const std::string name =
                    match[1].str();

                if (
                    name != "if" &&
                    name != "for" &&
                    name != "while" &&
                    name != "switch" &&
                    name != "catch"
                ) {

                    const std::size_t bracePosition =
                        line.find('{');

                    if (bracePosition != std::string::npos) {

                        FunctionInfo info;

                        info.name = name;
                        info.file = file;
                        info.line = currentLine;

                        info.lines = blockLineCount(
                            content,
                            lineStart + bracePosition
                        );

                        functions.push_back(info);
                    }
                }
            }
        }

        if (lineEnd == std::string::npos) {
            break;
        }

        lineStart = lineEnd + 1;
        ++currentLine;
    }

    return functions;
}

std::vector<ClassInfo> CodeLens::detectClasses(
    const std::string& content,
    const fs::path& file
) const
{
    std::vector<ClassInfo> classes;

    const std::regex pattern(
        R"(\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:[:][^{]+)?\s*\{)"
    );

    std::sregex_iterator begin(
        content.begin(),
        content.end(),
        pattern
    );

    const std::sregex_iterator end;

    for (auto it = begin; it != end; ++it) {

        const std::smatch& match = *it;

        if (match.size() < 2) {
            continue;
        }

        ClassInfo info;

        info.name = match[1].str();

        const std::size_t matchPosition =
            static_cast<std::size_t>(
                match.position(0)
            );

        const std::size_t namePosition =
            matchPosition +
            static_cast<std::size_t>(
                match.position(1)
            );

        info.file = file;
        info.line = lineNumber(
            content,
            namePosition
        );

        const std::size_t openingBrace =
            matchPosition +
            match.length() -
            1;

        std::size_t depth = 0;
        std::size_t endPosition = content.size();

        for (
            std::size_t i = openingBrace;
            i < content.size();
            ++i
        ) {
            if (content[i] == '{') {
                ++depth;
            }
            else if (content[i] == '}') {

                if (depth > 0) {
                    --depth;
                }

                if (depth == 0) {
                    endPosition = i;
                    break;
                }
            }
        }

        const std::string classBody =
            content.substr(
                openingBrace,
                endPosition - openingBrace
            );

        const std::regex methodPattern(
            R"(\b[A-Za-z_~][A-Za-z0-9_:~]*\s*\([^;{}]*\)\s*(?:const\s*)?(?:\{|;))"
        );

        std::sregex_iterator methodBegin(
            classBody.begin(),
            classBody.end(),
            methodPattern
        );

        std::sregex_iterator methodEnd;

        for (
            auto methodIt = methodBegin;
            methodIt != methodEnd;
            ++methodIt
        ) {
            ++info.methods;
        }

        classes.push_back(info);
    }

    return classes;
}

std::vector<StructInfo> CodeLens::detectStructs(
    const std::string& content,
    const fs::path& file
) const
{
    std::vector<StructInfo> structs;

    const std::regex pattern(
        R"(\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:[:][^{]+)?\s*\{)"
    );

    std::sregex_iterator begin(
        content.begin(),
        content.end(),
        pattern
    );

    const std::sregex_iterator end;

    for (auto it = begin; it != end; ++it) {

        const std::smatch& match = *it;

        if (match.size() < 2) {
            continue;
        }

        StructInfo info;

        info.name = match[1].str();

        const std::size_t matchPosition =
            static_cast<std::size_t>(
                match.position(0)
            );

        const std::size_t namePosition =
            matchPosition +
            static_cast<std::size_t>(
                match.position(1)
            );

        info.file = file;
        info.line = lineNumber(
            content,
            namePosition
        );

        structs.push_back(info);
    }

    return structs;
}

std::size_t CodeLens::lineNumber(
    const std::string& content,
    std::size_t position
) const
{
    std::size_t line = 1;

    const std::size_t limit =
        position < content.size()
            ? position
            : content.size();

    for (std::size_t i = 0; i < limit; ++i) {

        if (content[i] == '\n') {
            ++line;
        }
    }

    return line;
}

std::size_t CodeLens::blockLineCount(
    const std::string& content,
    std::size_t openingBrace
) const
{
    if (openingBrace >= content.size()) {
        return 0;
    }

    std::size_t depth = 0;
    std::size_t closingBrace = openingBrace;

    for (
        std::size_t i = openingBrace;
        i < content.size();
        ++i
    ) {

        if (content[i] == '{') {
            ++depth;
        }
        else if (content[i] == '}') {

            if (depth > 0) {
                --depth;
            }

            if (depth == 0) {
                closingBrace = i;
                break;
            }
        }
    }

    const std::size_t startLine =
        lineNumber(content, openingBrace);

    const std::size_t endLine =
        lineNumber(content, closingBrace);

    return endLine >= startLine
        ? endLine - startLine + 1
        : 0;
}

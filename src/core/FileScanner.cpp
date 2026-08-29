#include "FileScanner.h"

#include <algorithm>
#include <cctype>
#include <system_error>

std::vector<FileInfo> FileScanner::scan(
    const fs::path& root
) const
{
    std::vector<FileInfo> files;

    std::error_code error;

    if (!fs::exists(root, error) ||
        error ||
        !fs::is_directory(root, error) ||
        error) {
        return files;
    }

    fs::directory_options options =
        fs::directory_options::skip_permission_denied;

    fs::recursive_directory_iterator iterator(
        root,
        options,
        error
    );

    const fs::recursive_directory_iterator end;

    while (iterator != end) {

        if (error) {
            error.clear();
            iterator.increment(error);
            continue;
        }

        const fs::directory_entry& entry = *iterator;
        const fs::path path = entry.path();

        // --------------------------------------------------------
        // Directories
        // --------------------------------------------------------

        if (entry.is_directory(error)) {

            if (error) {
                error.clear();
                iterator.increment(error);
                continue;
            }

            if (shouldIgnoreDirectory(path)) {
                iterator.disable_recursion_pending();
            }

            iterator.increment(error);
            continue;
        }

        // --------------------------------------------------------
        // Regular source files
        // --------------------------------------------------------

        if (!error &&
            entry.is_regular_file(error) &&
            !error &&
            isSourceFile(path) &&
            !isGeneratedFile(path)) {

            std::error_code sizeError;

            const std::uintmax_t size =
                entry.file_size(sizeError);

            if (!sizeError) {
                files.push_back({
                    path,
                    size
                });
            }
        }

        error.clear();
        iterator.increment(error);
    }

    return files;
}

// ================================================================
// Directory filtering
// ================================================================

bool FileScanner::shouldIgnoreDirectory(
    const fs::path& path
) const
{
    const std::string name =
        toLower(path.filename().string());

    return
        // Version control
        name == ".git" ||
        name == ".svn" ||
        name == ".hg" ||

        // Dependencies
        name == "node_modules" ||
        name == "vendor" ||

        // Build/output directories
        name == "build" ||
        name == "builds" ||
        name == "dist" ||
        name == "target" ||
        name == "out" ||
        name == "bin" ||
        name == "obj" ||

        // IDE/cache directories
        name == ".idea" ||
        name == ".vscode" ||
        name == ".vs" ||
        name == ".cache" ||
        name == "__pycache__" ||

        // Common generated directories
        name == "generated" ||
        name == "generated-src";
}

// ================================================================
// Source file detection
// ================================================================

bool FileScanner::isSourceFile(
    const fs::path& path
) const
{
    const std::string extension =
        toLower(path.extension().string());

    return
        // C / C++
        extension == ".c" ||
        extension == ".cc" ||
        extension == ".cpp" ||
        extension == ".cxx" ||
        extension == ".h" ||
        extension == ".hh" ||
        extension == ".hpp" ||
        extension == ".hxx" ||

        // Python
        extension == ".py" ||

        // JavaScript / TypeScript
        extension == ".js" ||
        extension == ".jsx" ||
        extension == ".ts" ||
        extension == ".tsx" ||

        // Java
        extension == ".java";
}

// ================================================================
// Generated source detection
// ================================================================

bool FileScanner::isGeneratedFile(
    const fs::path& path
) const
{
    const std::string filename =
        toLower(path.filename().string());

    /*
        Avoid scanning generated source files.

        Examples:

            foo.generated.cpp
            foo.g.cpp
            generated_file.hpp
    */

    if (filename.find(".generated.") != std::string::npos) {
        return true;
    }

    if (filename.find(".g.cpp") != std::string::npos) {
        return true;
    }

    if (filename.find(".g.hpp") != std::string::npos) {
        return true;
    }

    if (filename.find(".gen.") != std::string::npos) {
        return true;
    }

    return false;
}

// ================================================================
// String helper
// ================================================================

std::string FileScanner::toLower(
    std::string value
)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char character) {
            return static_cast<char>(
                std::tolower(character)
            );
        }
    );

    return value;
}
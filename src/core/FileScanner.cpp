#include "FileScanner.h"

#include <system_error>

std::vector<FileInfo> FileScanner::scan(
    const fs::path& root) const
{
    std::vector<FileInfo> files;

    std::error_code error;

    if (!fs::exists(root, error) ||
        !fs::is_directory(root, error)) {
        return files;
    }

    fs::recursive_directory_iterator iterator(
        root,
        fs::directory_options::skip_permission_denied,
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

        if (entry.is_directory(error)) {

            if (shouldIgnoreDirectory(path)) {
                iterator.disable_recursion_pending();
            }

            iterator.increment(error);
            continue;
        }

        if (!error &&
            entry.is_regular_file(error) &&
            isSourceFile(path)) {

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

        iterator.increment(error);
    }

    return files;
}

bool FileScanner::shouldIgnoreDirectory(
    const fs::path& path) const
{
    const std::string name =
        path.filename().string();

    return
        name == ".git" ||
        name == ".svn" ||
        name == ".hg" ||
        name == "node_modules" ||
        name == "build" ||
        name == "dist" ||
        name == "target" ||
        name == ".idea" ||
        name == ".vscode";
}

bool FileScanner::isSourceFile(
    const fs::path& path) const
{
    const std::string extension =
        path.extension().string();

    return
        extension == ".cpp" ||
        extension == ".cc" ||
        extension == ".cxx" ||
        extension == ".h" ||
        extension == ".hpp" ||
        extension == ".hh" ||
        extension == ".c" ||
        extension == ".py" ||
        extension == ".js" ||
        extension == ".jsx" ||
        extension == ".ts" ||
        extension == ".tsx" ||
        extension == ".java";
}
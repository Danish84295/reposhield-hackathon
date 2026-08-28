#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct FileInfo {
    fs::path path;
    std::uintmax_t size;
};

class FileScanner {
public:
    std::vector<FileInfo> scan(const fs::path& root) const;

private:
    bool shouldIgnoreDirectory(const fs::path& path) const;
    bool isSourceFile(const fs::path& path) const;
};
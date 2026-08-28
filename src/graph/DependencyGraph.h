#pragma once

#include "../supplychain/DependencyAnalyzer.h"

#include <string>
#include <vector>

struct DependencyEdge {
    fs::path source;
    std::string target;
    DependencyType type;
};

class DependencyGraph {
public:
    std::vector<DependencyEdge> build(
        const std::vector<DependencyInfo>& dependencies
    ) const;

    void print(
        const std::vector<DependencyEdge>& edges
    ) const;
};

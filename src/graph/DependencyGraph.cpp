#include "DependencyGraph.h"

#include <iostream>

std::vector<DependencyEdge> DependencyGraph::build(
    const std::vector<DependencyInfo>& dependencies
) const
{
    std::vector<DependencyEdge> edges;

    for (const DependencyInfo& dependency : dependencies) {
        edges.push_back({
            dependency.file,
            dependency.name,
            dependency.type
        });
    }

    return edges;
}

void DependencyGraph::print(
    const std::vector<DependencyEdge>& edges
) const
{
    if (edges.empty()) {
        std::cout
            << "No dependency relationships detected.\n\n";
        return;
    }

    fs::path currentFile;

    for (const DependencyEdge& edge : edges) {

        if (edge.source != currentFile) {

            currentFile = edge.source;

            std::cout
                << "\n"
                << currentFile.string()
                << "\n";
        }

        std::cout
            << "  +-- ["
            << DependencyAnalyzer::typeToString(edge.type)
            << "] "
            << edge.target
            << "\n";
    }

    std::cout << "\n";
}
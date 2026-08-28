cmake_minimum_required(VERSION 3.16)

project(RepoShield
    VERSION 0.1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(reposhield
    src/main.cpp

    src/core/FileScanner.cpp

    src/codelens/CodeLens.cpp

    src/security/SecurityAnalyzer.cpp

    src/supplychain/DependencyAnalyzer.cpp
)

target_include_directories(reposhield PRIVATE
    src
)

if (MSVC)
    target_compile_options(reposhield PRIVATE /W4)
else()
    target_compile_options(reposhield PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()
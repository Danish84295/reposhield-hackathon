#include <cstring>
#include <cstdlib>
#include <iostream>

void unsafeCopy(const char* input) {
    char buffer[20];
    strcpy(buffer, input);
    std::cout << buffer << std::endl;
}

void executeCommand(const char* command) {
    system(command);
}

int main() {
    unsafeCopy("demo input");
    executeCommand("echo RepoShield demo");
    return 0;
}

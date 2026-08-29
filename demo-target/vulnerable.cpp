#include <cstring>
#include <cstdlib>
#include <iostream>

struct UserInfo {
    int id;
    const char* name;
};

class DemoProcessor {
public:
    void process() {
        std::cout << "Processing demo";
    }

    int calculate(int value) {
        if (value > 10) {
            return value * 2;
        }

        return value;
    }
};

void unsafeCopy(const char* input) {
    char buffer[20];
    strcpy(buffer, input);
    std::cout << buffer << std::endl;
}

void executeCommand(const char* command) {
    system(command);
}

int main() {
    DemoProcessor processor;

    processor.process();

    unsafeCopy("demo input");
    executeCommand("echo RepoShield demo");

    return 0;
}

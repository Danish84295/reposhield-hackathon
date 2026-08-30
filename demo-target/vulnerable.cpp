#include <cstring>
#include <cstdlib>
#include <iostream>
#include <cstdio>
#include <string>
#include <openssl/sha.h>

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


void securityDemo()
{
    const char* password = "demo-secret-password";

    // Weak cryptography
    const char* algorithm = "MD5";

    // Dangerous file operation
    FILE* file = fopen("demo.txt", "r");

    // Potential SQL injection
    std::string userInput = "admin";
    std::string query =
        "SELECT * FROM users WHERE name = " + userInput;

    // Insecure random generation
    srand(1234);
    int value = rand();

    std::cout << password
              << algorithm
              << query
              << value;

    if (file) {
        fclose(file);
    }
}

int main() {
    DemoProcessor processor;

    processor.process();

    unsafeCopy("demo input");
    executeCommand("echo RepoShield demo");

    return 0;
}

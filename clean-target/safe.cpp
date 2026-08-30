#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

int calculateSum(const std::vector<int>& values)
{
    int sum = 0;

    for (int value : values) {
        sum += value;
    }

    return sum;
}

std::string greet(const std::string& name)
{
    if (name.empty()) {
        return "Hello, user!";
    }

    return "Hello, " + name + "!";
}

int main()
{
    std::vector<int> values = {1, 2, 3, 4, 5};

    std::cout << "Sum: "
              << calculateSum(values)
              << std::endl;

    std::cout << greet("RepoShield")
              << std::endl;

    return 0;
}
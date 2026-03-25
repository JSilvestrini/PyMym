#include <thread>
#include <chrono>
#include <iostream>

__declspec(noinline) void trashFunction(volatile intptr_t* val) {
    if (&val == 0) { printf("Zero"); }
}

intptr_t stackTest() {
    std::cout << "STARTING STACK" << std::endl;
    volatile intptr_t searchval = 0xDEADB33FFEEDCAFE;
    trashFunction(&searchval);
    std::cout << searchval << " IS NOW ON THE STACK" << std::endl;

    std::this_thread::sleep_for(std::chrono::seconds(10));
    return reinterpret_cast<intptr_t>(&searchval);
}

int main() {
    std::cout << stackTest() << std::endl;
}
#include <thread>
#include <chrono>
#include <iostream>
#include <intrin.h>

__declspec(noinline) void trashFunction2(volatile intptr_t* val) {
    if (&val == 0) {
        printf("Zero");
    }
}

__declspec(noinline) void trashFunction(volatile intptr_t* val) {
    trashFunction2(val);
}

__declspec(noinline) void trashFunction(std::string* val, int c) {
    if (c < 10) {
        trashFunction(val, c + 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

int main() {
    volatile intptr_t searchval = 0xDEADB33FFEEDCAFE;
    volatile intptr_t* search2 = new intptr_t(0xFEEDCAFEDEADB33F);
    trashFunction(&searchval);
    std::string searchString = "This string should be on the heap. Hopefully";
    char stackstring[] = "This string should be on the stack. Hopefully";

    int c = 0;
    while (c < 10) {
        trashFunction(&searchString, 0);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        c++;
    }
    std::cout << searchval << std::endl;
    std::cout << search2 << std::endl;
    std::cout << searchString << std::endl;
    std::cout << stackstring << std::endl;

    delete(search2);
}
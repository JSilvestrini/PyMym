cmake_minimum_required(VERSION 3.18)
project(_lib)

find_package(Python3 REQUIRED COMPONENTS Interpreter Development.Module)
find_package(pybind11 CONFIG REQUIRED)

pybind11_add_module(_lib SHARED src/cpp/src_PyMym.cpp)

set_target_properties(_lib PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON PREFIX "")

install(TARGETS _lib DESTINATION PyMym/backend)

install(DIRECTORY src/PyMym/ DESTINATION PyMym
        FILES_MATCHING PATTERN "*.py" PATTERN "*.pyi"
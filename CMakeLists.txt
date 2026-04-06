cmake_minimum_required(VERSION 3.18)
project(_lib)

find_package(Python3 REQUIRED COMPONENTS Interpreter Development)

execute_process(
    COMMAND "${Python3_EXECUTABLE}" -m pybind11 --cmakedir
    OUTPUT_VARIABLE pybind11_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

set(pybind11_DIR ${pybind11_DIR})

message(STATUS "Using pybind11 found at: ${pybind11_DIR}")
find_package(pybind11 CONFIG REQUIRED PATHS "${pybind11_DIR}" NO_DEFAULT_PATH)

pybind11_add_module(_lib SHARED src/cpp/src_PyMym.cpp)

set_target_properties(_lib PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)

add_custom_command(TARGET _lib POST_BUILD
COMMAND ${CMAKE_COMMAND} -E copy
$<TARGET_FILE_DIR:_lib>/$<TARGET_FILE_NAME:_lib>
${CMAKE_SOURCE_DIR}/src/PyMym/backend/$<TARGET_FILE_NAME:_lib>
)
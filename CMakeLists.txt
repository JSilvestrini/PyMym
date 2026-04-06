cmake_minimum_required(VERSION 3.18)
project(_lib)

set(PYTHON_VENV_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../PyWin-Memr" CACHE PATH "Path to Python virtual environment")

# 2. Tell FindPython3 to look specifically in the venv
set(Python3_ROOT_DIR ${PYTHON_VENV_PATH})
set(Python3_FIND_STRATEGY LOCATION)
set(Python3_FIND_VIRTUALENV ONLY)

find_package (Python3 3.14 EXACT REQUIRED COMPONENTS Interpreter Development REQUIRED)

execute_process(
COMMAND ${Python3_EXECUTABLE} -m pybind11 --cmakedir
OUTPUT_VARIABLE pybind11_cmake_dir
OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(pybind11_DIR ${pybind11_cmake_dir})

message(STATUS "Using pybind11 found at: ${pybind11_DIR}")
find_package(pybind11 REQUIRED)

pybind11_add_module(_lib SHARED src/cpp/src_PyMym.cpp)

set_target_properties(_lib PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)

add_custom_command(TARGET _lib POST_BUILD
COMMAND ${CMAKE_COMMAND} -E copy
$<TARGET_FILE_DIR:_lib>/$<TARGET_FILE_NAME:_lib>
${CMAKE_SOURCE_DIR}/src/PyMym/backend/$<TARGET_FILE_NAME:_lib>
)
cmake_minimum_required(VERSION 3.18)
project(
${SKBUILD_PROJECT_NAME}
LANGUAGES CXX
)

find_package(Python COMPONENTS Interpreter Development)
find_package(pybind11 CONFIG REQUIRED)

python_add_library(_lib MODULE src/src_PyMym WITH_SOABI)
target_link_libraries(_lib PRIVATE pybind11::headers)
set_target_properties(_lib PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON PREFIX "")

install(TARGETS _lib DESTINATION ${SKBUILD_PROJECT_NAME}/backend)
cmake_minimum_required(VERSION 3.18)
project(
${SKBUILD_PROJECT_NAME}
VERSION ${SKBUILD_PROJECT_VERSION}
LANGUAGES CXX
)

find_package(pybind11 CONFIG REQUIRED)

# Find pybind11 and Python
find_package(pybind11 CONFIG REQUIRED)

python_add_library(_core MODULE src/cpp/src_PyMym WITH_SOABI)
target_link_libraries(_lib PRIVATE pybind11::headers)
set_target_properties(_lib PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON PREFIX "")

install(TARGETS _lib DESTINATION PyMym/backend)
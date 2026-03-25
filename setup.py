from setuptools import find_packages, setup

#put required libraries here
setup(
    name='PyMym',
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "PyMym": ["*.pyd", "*.so", "*.pyi"],
    },
    version='0.1.0',
    description='A Python library for memory manipulation in Windows',
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author='Julian Silvestrini',
    url="https://github.com/JSilvestrini/PyMym",
    install_requires=[],
    #setup_requires=['pytest-runner'],
    #tests_require=['pytest'],
    #test_suite='tests',
)
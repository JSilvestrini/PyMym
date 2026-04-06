from setuptools import find_packages, setup

#put required libraries here
setup(
    name='PyMym',
    package_dir={"": "src"},
    packages=find_packages(where="src", include=["PyMym"]),
    include_package_data=True,
    package_data={
        "PyMym": ["*.pyd", "*.pyi"],
    },
    version='1.0.0',
    description='A Python library for memory manipulation in Windows',
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author='Julian Silvestrini',
    url="https://github.com/JSilvestrini/PyMym",
    install_requires=['pywin32'],
)
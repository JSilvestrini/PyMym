from setuptools import setup, Extension

setup(
    ext_modules=[Extension("PyMym.backend._lib", sources=[])]
)
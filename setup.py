from setuptools import setup
from setuptools import find_packages

setup(
    name='cryptolib',
    version='0.1.0',
    description='crypto library for CTF',
    author='miso',
    packages=['cryptolib'],
    package_dir={'cryptolib': 'src'},
    install_requires=['gmpy2']
)

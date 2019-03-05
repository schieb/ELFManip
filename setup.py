from setuptools import setup

setup(
    name='elfmanip',
    version='0.2.1',
    description='A library for manipulating ELF files',
    packages=['elfmanip'],
    python_requires='>=2.7,!=3.*',
    install_requires=[
        'pyelftools>=0.25',
    ],
)

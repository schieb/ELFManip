from setuptools import setup

setup(
	name='elfmanip',
	version='0.2.0',
	description='A library for manipulating ELF files',
	packages=['elfmanip'],
	install_requires=['pyelftools'],
)

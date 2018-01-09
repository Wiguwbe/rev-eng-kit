from distutils.core import setup, Extension

setup(
	name='elfr',
	version="1.0",
	ext_modules = [ Extension('elfr',['lib_elf_reader.c']) ]
)

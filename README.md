# rev-eng-kit

Reverse Engineering (Tool)Kit

This is a Python script accompanied by a custom library

---

### The Library

*elfr* or ELF Reader
Is a library which permits *simpler* read access to ELF Files

It allows to:
1. Read Section Headers
2. Decompile (using objdump) a section
3. Get a string from a memory address
4. Get an integer from a memory address
5. Dump the contents of a section header

This module brings two new classes to Python
- *elfr*.File - this is the Elf File handler
- *elfr*.SecHdr - this holds information on a Section Header

#### *elfr*.File

---

File(file_name)

`Opens a file and checks if it's a ELF File through its magic`

File.readfile()

`Reads the file's section headers into a list of *SecHdr*s`

File.gets(where,max)

`Reads a string from (memory) address *where* of max length of *max*`

File.geti(where,size)

`Reads an integer from (memory) address *where* of size *size* (1,2,4 or 8)`

File.dumps(section)

`Dumps content of Section with name *section* into a String`

File.decompile(section)

`Decompiles Section with name *section*, using objdump, into a string`

File.fd

`The file descriptor`

File.fname

`The file name`

File.info

`Ignore`

File.sections

`List of *SecHdr*s`

#### *elfr*.SecHdr

SecHdr.is_alloc()

`Checks if has flag *alloc*`

SecHdr.is_exec()

`Checks if has flag *exec*`

SecHdr.is_merge()

`Checks if has flag *merge*`

SecHdr.is_strings()

`Checks if has flag *strings*`

SecHdr.is_write()

`Checks if has flag *write*`

SecHdr.address

`Section's start address on RAM`

SecHdr.flags

`Section's flags`

SecHdr.name

`Section's name (used to 'talk' with *elfr.File*)`

SecHdr.offset

`Section's offset on file`

SecHdr.size

`Section's size`

---

### The Script

The script runs creating a *elfr.File* object, opening a file provided through *sys.argv*

In it's simplest form, it runs by:
1. Preparing the dump output by extracting 'header' lines and identifying loops (if/else, for/while and do..while)
2. In the core it 'runs' the code top down, but keeping track of what variables/stack values are passed around in the registers
3. Finalizing the code by identing so it can be *viewable*

Its global variables are, amongst some helper dictionaries and lists:

**f**: holding the *elfr.File* object

**code**: holding the final code as a string

The final code still has memory values (such as `-0x4(%rbp)`) which you can replace after

The functions called will have some parameters in it, which may be wrong ( the amount of params )

In general, if possible, strings loaded with `lea` will have and integer ( which in case of strings, will be possible to fetch through *f.gets(value,max)*

---

### Building the Library

Building the library should be a simple task

`$ cd` into the repository

`$ cd lib/`

`$ python setup.py build`

There should be a new folder `build/lib-something-some-numbers/` with an object file `elfr.so`

This is the library

To install, simply, in the `lib/` run (you may need root)

`$ python setup.py install`

After this, you should be able to use the library from anywhere

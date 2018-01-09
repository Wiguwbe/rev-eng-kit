/**
 *
 * Elf Reader Module for Python
 *
 * 'elfr'
 *
 *
 * Copyright Tiago Teixeira, 2018
 *
**/
#include <Python.h>
#include "structmember.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

//
// ELF Section Header Class
//
typedef struct
{
	PyObject_HEAD
	PyObject*name;	// using Python Strings
	long address;	// on RAM
	long offset;	// on FILE
	long flags;	// necessary?
	long size;	// size
} eSecHdr;

// dealloc
static void SecHdr_dealloc(eSecHdr*self)
{
	Py_XDECREF(self->name);
	Py_TYPE(self)->tp_free((PyObject*)self);
}
// new
static PyObject* SecHdr_new(PyTypeObject*type,PyObject*args,PyObject*kwds)
{
	eSecHdr*self;

	self = (eSecHdr*)type->tp_alloc(type,0);
	if(self!=NULL)
	{
		self->name = PyString_FromString("");
		if(self->name==NULL)
		{
			Py_DECREF(self);
			return NULL;
		}
		self->address=0;
		self->offset=0;
		self->flags=0;
		self->size=0;
	}
	return (PyObject*)self;
}
// init
static int SecHdr_init(eSecHdr*self,PyObject*args,PyObject*kwds)
{
	PyObject *name = NULL,*tmp;
	static char *kwlist[] = {"name","address","offset","flags","size",NULL};
	if(!PyArg_ParseTupleAndKeywords(args,kwds,"|Sllll",kwlist,&name,&self->address,&self->offset,&self->flags,&self->size))
		return -1;
	if(name)
	{
		tmp=self->name;
		Py_INCREF(name);
		self->name=name;
		Py_XDECREF(tmp);
	}
	return 0;
}
// getters
static PyObject*SecHdr_getname(eSecHdr*self,void*closure)
{
	return Py_BuildValue("S",self->name);
}
static PyObject*SecHdr_getaddress(eSecHdr*self,void*closure)
{
	return Py_BuildValue("l",self->address);
}
static PyObject*SecHdr_getoffset(eSecHdr*self,void*closure)
{
	return Py_BuildValue("l",self->offset);
}
static PyObject*SecHdr_getflags(eSecHdr*self,void*closure)
{
	return Py_BuildValue("l",self->flags);
}
static PyObject*SecHdr_getsize(eSecHdr*self,void*closure)
{
	return Py_BuildValue("l",self->size);
}
static int SecHdr_setname(eSecHdr*self,PyObject*v,void*closure)
{
	if(v==NULL)
	{
		PyErr_SetString(PyExc_TypeError,"Cannot delete name attribute");
		return -1;
	}
	if(!PyString_Check(v))
	{
		PyErr_SetString(PyExc_TypeError,"The name attribute must be a string");
		return -1;
	}
	Py_DECREF(self->name);
	Py_INCREF(v);
	self->name=v;
	return 0;
}

// general 'blocking' getter
static int SecHdr_setattr(eSecHdr*self,PyObject*v,void*closure)
{
	PyErr_SetString(PyExc_Exception,"Cannot set attribute");
	return -1;
}
// methods
// mostly is_*
static PyObject*SecHdr_is_exec(eSecHdr*self,PyObject*args)
{
	if(self->flags&4)
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}
static PyObject*SecHdr_is_write(eSecHdr*self,PyObject*args)
{
	if(self->flags&1)
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}
static PyObject*SecHdr_is_alloc(eSecHdr*self,PyObject*args)
{
	if(self->flags&2)
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}
static PyObject*SecHdr_is_merge(eSecHdr*self,PyObject*args)
{
	if(self->flags&0x10)
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}
static PyObject*SecHdr_is_strings(eSecHdr*self,PyObject*args)
{
	if(self->flags&0x20)
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

// Struct Declarations
static PyMemberDef SecHdr_members[] = {
//	{"name",T_OBJECT,offsetof(eSecHdr,name),0,"section name"},
	{"address",T_LONG,offsetof(eSecHdr,address),0,"section address on RAM"},
	{"offset",T_LONG,offsetof(eSecHdr,offset),0,"section offset on file"},
	{"flags",T_LONG,offsetof(eSecHdr,flags),0,"section flags"},
	{"size",T_LONG,offsetof(eSecHdr,size),0,"section size"},
	{NULL}	// sentinel
};
static PyGetSetDef SecHdr_getseters[] = {
	{"name",(getter)SecHdr_getname,(setter)SecHdr_setattr,"section name"},
//	{"address",(getter)SecHdr_getaddress,(setter)SecHdr_setattr,"section address"},
//	{"offset",(getter)SecHdr_getoffset,(setter)SecHdr_setattr,"section offset"},
//	{"flags",(getter)SecHdr_getflags,(setter)SecHdr_setattr,"section flags"},
//	{"size",(getter)SecHdr_getsize,(setter)SecHdr_setattr,"section size"},
	{NULL}
};
static PyMethodDef SecHdr_methods[] = {
	{"is_exec",(PyCFunction)SecHdr_is_exec,METH_NOARGS,"Checks if section is EXEC"},
	{"is_write",(PyCFunction)SecHdr_is_write,METH_NOARGS,"Checks if section is WRITE"},
	{"is_alloc",(PyCFunction)SecHdr_is_alloc,METH_NOARGS,"Checks if section is ALLOC"},
	{"is_merge",(PyCFunction)SecHdr_is_merge,METH_NOARGS,"Checks if section is MERGE"},
	{"is_strings",(PyCFunction)SecHdr_is_strings,METH_NOARGS,"Checks if section if STRINGS"},
	{NULL}
};
static PyTypeObject SecHdrType = {
	PyVarObject_HEAD_INIT(NULL,0)
	"elfr.SecHdr",	// name
	sizeof(eSecHdr),	// basic size
	0,	// item size
	(destructor)SecHdr_dealloc,	// dealloc
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,	// flags
	"SecHdr objects",	// doc
	0,
	0,
	0,
	0,
	0,
	0,
	SecHdr_methods,	// methods
	SecHdr_members,
	SecHdr_getseters,
	0,
	0,
	0,
	0,
	0,
	(initproc)SecHdr_init,
	0,
	SecHdr_new,
};


//
// (ELF) File Class
//
typedef struct
{
	PyObject_HEAD
	PyObject*fname;	// name of elf_file as PyString
	PyObject*sec_hdrs;	// List of 'elf_SecHdr's
	int fd;	// file descriptor
	int info;	// some flags info (e.g. endianess, platform, arch ...)
} eFile;

// dealloc
static void File_dealloc(eFile*self)
{
	Py_XDECREF(self->sec_hdrs);
	Py_XDECREF(self->fname);
	if(self->fd!=-1)
		close(self->fd);
	Py_TYPE(self)->tp_free((PyObject*)self);
}
// new
static PyObject*File_new(PyTypeObject*type,PyObject*args,PyObject*kwds)
{
	eFile*self;
	self=(eFile*)type->tp_alloc(type,0);
	if(self!=NULL)
	{
		self->sec_hdrs = PyList_New(0);
		if(self->sec_hdrs==NULL)
		{
			Py_DECREF(self);
			return NULL;
		}
		self->fname=PyString_FromString("");
		if(self->fname==NULL)
		{
			Py_DECREF(self);
			return NULL;
		}
		self->fd=-1;
		self->info=0;
	}
	return (PyObject*)self;
}
// init
static int File_init(eFile*self,PyObject*args,PyObject*kwds)
{
	PyObject*name=NULL,*tmp;
	if(!PyArg_ParseTuple(args,"S",&name))
	{
		PyErr_SetString(PyExc_ValueError,"Expected a string as parameter");
		return -1;
	}
	if(name!=NULL)
	{
		tmp=self->fname;
		Py_INCREF(name);
		self->fname=name;
		Py_DECREF(tmp);
	}
	char buffer[16];
	// open file
	self->fd=open(PyString_AsString(self->fname),O_RDONLY);
	if(self->fd==-1)
	{
		PyErr_SetString(PyExc_Exception,"Failed to open file");
		return -1;
	}
	// check if is ELF
	if(read(self->fd,buffer,4)!=4)
	{
		PyErr_SetString(PyExc_IOError,"Failed to read from file");
		return -1;
	}
	if(strncmp("ELF",buffer+1,3)||*buffer!=0x7f)
	{
		PyErr_SetString(PyExc_IOError,"File is not ELF");
		return -1;
	}
	return 0;
}

//
// Main Methods
//
/*
 TODO:
 X	file.readfile
 X	file.gets(where,max)
 X	file.geti(where,size)
 X	file.dumps(section)

 X	implement get/sets
*/
static PyObject*File_readfile(eFile*self,PyObject*args)
{
	PyObject*tmp = NULL;
	char buffer[16];
	int names[32];
	int bufi,off1,off2,h1,h2;
	lseek(self->fd,0,SEEK_SET);
	if(read(self->fd,buffer,5)!=5)
	{
		PyErr_SetString(PyExc_IOError,"Failed to read from file");
		return NULL;
	}
	// info[0] -> bitness
	self->info |= buffer[4]-1;	// bit-ness (0->32-bit, 1->64-bit)

	// section header table
	lseek(self->fd,self->info&1?0x28:0x20,SEEK_SET);
	if(read(self->fd,&off1,self->info&1?8:4)<0)
	{
		PyErr_SetString(PyExc_IOError,"Failed to read from file");
		return NULL;
	}
	// number of section entries
	lseek(self->fd,self->info&1?0x3c:0x30,SEEK_SET);
	if(read(self->fd,&h1,2)!=2)
	{
		PyErr_SetString(PyExc_IOError,"Failed to read from file");
		return NULL;
	}
	// .shstrtab index
	if(read(self->fd,&h2,2)!=2)
	{
		PyErr_SetString(PyExc_IOError,"Failed to read from file");
		return NULL;
	}
	// save h2 index
	self->info|=(h2&0xffff)<<1;

	// Alloc new list
	/*
	tmp = PyList_New(h1);
	if(tmp!=NULL)
	{
		Py_XDECREF(self->sec_hdrs);
		self->sechdrs=tmp;
	}
	// will not alloc, keep with list[0]
	// will use list.append(item);
	else
	{
		PyErr_SetString(PyExc_Exception,"Failed to allocate list");
		return NULL;
	}
	*/
	// read all sections
	lseek(self->fd,off1,SEEK_SET);
	for(int i=0;i<h1;i++)
	{
		long a,o,f,s;
		int n;
		// assume no errors?
		read(self->fd,names+i,4);
		lseek(self->fd,4,SEEK_CUR);
		read(self->fd,&f,self->info&1?8:4);
		read(self->fd,&a,self->info&1?8:4);
		read(self->fd,&o,self->info&1?8:4);
		read(self->fd,&s,self->info&1?8:4);
		lseek(self->fd,self->info&1?24:16,SEEK_CUR);
		// create object
		PyObject*kwds = PyDict_New();
		PyObject*pa,*po,*pf,*ps,*args;
		pa = PyLong_FromLong(a);
		po = PyLong_FromLong(o);
		pf = PyLong_FromLong(f);
		ps = PyLong_FromLong(s);
		args = PyTuple_New(0);
		PyDict_SetItemString(kwds,"address",pa);
		PyDict_SetItemString(kwds,"offset",po);
		PyDict_SetItemString(kwds,"flags",pf);
		PyDict_SetItemString(kwds,"size",ps);
		PyObject*item = PyObject_Call((PyObject*)&SecHdrType,args,kwds);
		PyList_Append(self->sec_hdrs,item);
		// free all
		Py_DECREF(kwds);
		Py_DECREF(args);
		Py_DECREF(pa);
		Py_DECREF(po);
		Py_DECREF(pf);
		Py_DECREF(ps);
		Py_DECREF(item);
/*
		// trying direct access...
		PyObject*args = PyTuple_New(0);
		PyObject*item = PyObject_Call((PyObject*)&SecHdrType,args,NULL);
		eSecHdr*obj = (eSecHdr*)item;
		obj->address=a;
		obj->offset=o;
		obj->flags=f;
		obj->size=s;
*/
		// save .shstrtab offset
		if(i==h2)
			off2=o;
	}

	// set names on sections
	for(int i=0;i<h1;i++)
	{
		PyObject*item = PyList_GetItem(self->sec_hdrs,i);
		lseek(self->fd,off2+names[i],SEEK_SET);
		read(self->fd,buffer,15);
		buffer[15]=0;	// safety
		// set name
		PyObject*name = PyString_FromString(buffer);
		SecHdr_setname((eSecHdr*)item,name,NULL);
		Py_DECREF(name);
	}
	Py_RETURN_TRUE;
}

static PyObject*File_gets(eFile*self,PyObject*args)
{
	long where;
	int max,len,i;
	char*out;
	PyObject*item;
	// go for each section item
	// check if 'where' is between address and size
	// true -> gets()
	if(!PyArg_ParseTuple(args,"li",&where,&max))
		return NULL;
	out = (char*)malloc(max+1);	// sentinel
	if(out==NULL)
	{
		// oops
		PyErr_SetString(PyExc_MemoryError,"Failed to allocate memory");
		return NULL;
	}
	len = PyList_Size(self->sec_hdrs);
	for(i=0;i<len;i++)
	{
		item = PyList_GetItem(self->sec_hdrs,i);
		if(PyObject_TypeCheck(item,&SecHdrType))
		{
			PyObject *ro,*oo,*so;
			long ram,offset,size;
			ro = SecHdr_getaddress((eSecHdr*)item,NULL);
			oo = SecHdr_getoffset((eSecHdr*)item,NULL);
			so = SecHdr_getsize((eSecHdr*)item,NULL);
			ram = PyLong_AsLong(ro);
			offset = PyLong_AsLong(oo);
			size = PyLong_AsLong(so);
			Py_DECREF(ro);
			Py_DECREF(oo);
			Py_DECREF(so);
			if(where>=ram&&where<(ram+size))
			{
				// found it
				lseek(self->fd,offset+where-ram,SEEK_SET);
				read(self->fd,out,max<size?max:size-1);
				out[max<size?max:size-1]=0;	// sentinel
				break;
			}
		}
	}
	if(i==len)
	{
		PyErr_SetString(PyExc_IndexError,"There is no such memory address");
		return NULL;
	}
	PyObject*ret=PyString_FromString(out);
	free(out);
	return ret;
}

static PyObject*File_geti(eFile*self,PyObject*args)
{
	long where,out;
	int size,i,len;
	PyObject*item;
	if(!PyArg_ParseTuple(args,"li",&where,&size))
		return NULL;
	if(size<1)
	{
		PyErr_SetString(PyExc_ValueError,"Size must be positive (1,2,4 or 8)");
		return NULL;
	}
	size = (size+4)>8?8:(size+1)&4?4:size;
	len = PyList_Size(self->sec_hdrs);
	for(i=0;i<len;i++)
	{
		item = PyList_GetItem(self->sec_hdrs,i);
		if(PyObject_TypeCheck(item,&SecHdrType))
		{
			PyObject *ro,*so,*oo;
			long ram,ssize,off;
			ro = SecHdr_getaddress((eSecHdr*)item,NULL);
			so = SecHdr_getsize((eSecHdr*)item,NULL);
			oo = SecHdr_getoffset((eSecHdr*)item,NULL);
			off = PyLong_AsLong(oo);
			ram = PyLong_AsLong(ro);
			ssize=PyLong_AsLong(so);
			Py_DECREF(ro);
			Py_DECREF(oo);
			Py_DECREF(so);
			if(where>=ram&&where<(ram+ssize))
			{
				// cool
				lseek(self->fd,off+where-ram,SEEK_SET);
				read(self->fd,&out,size);
				break;
			}
		}
	}
	if(i==len)
	{
		PyErr_SetString(PyExc_IndexError,"There is no such memory address");
		return NULL;
	}
	return size&8?PyLong_FromLong(out):PyInt_FromLong(out);
}

static PyObject*File_dumps(eFile*self,PyObject*args)
{
	PyObject*item,*string,*offset,*size;
	int len,i,fsize;
	const char*sec;
	char*out;
	if(!PyString_Check(args))
	{
		PyErr_SetString(PyExc_ValueError,"Section should be a string");
		return NULL;
	}
	sec=PyString_AsString(args);
	len = PyList_Size(self->sec_hdrs);
	for(i=0;i<len;i++)
	{
		item = PyList_GetItem(self->sec_hdrs,i);
		if(PyObject_TypeCheck(item,&SecHdrType))
		{
			string = SecHdr_getname((eSecHdr*)item,NULL);
			if(!strcmp(sec,PyString_AsString(string)))
			{
				long off,s;
				offset = SecHdr_getoffset((eSecHdr*)item,NULL);
				size = SecHdr_getsize((eSecHdr*)item,NULL);
				off = PyLong_AsLong(offset);
				s = PyLong_AsLong(size);
				Py_DECREF(offset);
				Py_DECREF(size);
				out=(char*)malloc(s+1);
				if(out==NULL)
				{
					PyErr_SetString(PyExc_MemoryError,"Failed to allocate memory");
					return NULL;
				}
				out[s]=0;
				lseek(self->fd,off,SEEK_SET);
				fsize=read(self->fd,out,s);
				Py_DECREF(string);
				break;
			}
			Py_DECREF(string);
		}
	}
	if(len==i)
	{
		PyErr_SetString(PyExc_KeyError,"There is no such section");
		return NULL;
	}
	PyObject*ret = PyString_FromStringAndSize(out,fsize);
	free(out);
	return ret;
}
static PyObject*File_decompile(eFile*self,PyObject*args)
{
	// decompile a section if EXEC flag is on
	PyObject *item,*sec_name,*out,*tmp;
	FILE*pipe;
	int len,i;
	long flags;
	const char*arg,*sec;
	char*buffer;
	if(!PyString_Check(args))
	{
		PyErr_SetString(PyExc_ValueError,"Section should be a string");
		return NULL;
	}
	buffer=(char*)malloc(128);	// buffering
	if(buffer==NULL)
	{
		PyErr_SetString(PyExc_MemoryError,"Failed to allocate memory");
		return NULL;
	}
	arg=PyString_AsString(args);
	len=PyList_Size(self->sec_hdrs);
	for(i=0;i<len;i++)
	{
		item = PyList_GetItem(self->sec_hdrs,i);
		if(PyObject_TypeCheck(item,&SecHdrType))
		{
			sec_name = SecHdr_getname((eSecHdr*)item,NULL);
			sec=PyString_AsString(sec_name);
			Py_DECREF(sec_name);
			if(!strcmp(sec,arg))
				// found it
				break;
		}
	}
	if(i==len)
	{
		PyErr_SetString(PyExc_KeyError,"There is no such section");
		free(buffer);
		return NULL;
	}
	// check flags (0x4)
	sec_name = SecHdr_getflags((eSecHdr*)item,NULL);	// reuse sec_name
	flags = PyLong_AsLong(sec_name);
	Py_DECREF(sec_name);
	if(!(flags&0x4))
	{
		PyErr_SetString(PyExc_Exception,"Section is not executable");
		free(buffer);
		return NULL;
	}
	out=PyString_FromString("");
	if(out==NULL)
	{
		PyErr_SetString(PyExc_MemoryError,"Failed to allocate memory");
		free(buffer);
		return NULL;
	}
	sprintf(buffer,"/bin/objdump -d -j %s %s",arg,PyString_AsString(self->fname));
	pipe = popen(buffer,"r");
	if(pipe==NULL)
	{
		PyErr_SetString(PyExc_SystemError,"Failed to create process");
		free(buffer);
		return NULL;
	}
	while((len=fread(buffer,1,127,pipe))==127)
	{
		buffer[127]=0;	// sentinel
		tmp = PyString_FromString(buffer);
		PyString_Concat(&out,tmp);
		Py_DECREF(tmp);	// temporarly free tmp
	}
	// last read
	if(len>0)
	{
		buffer[len]=0;	// sentinel
		tmp = PyString_FromString(buffer);
		PyString_Concat(&out,tmp);
		Py_DECREF(tmp);
	}
	// free res
	free(buffer);
	pclose(pipe);
	return out;
}

// getters
static PyObject*File_fd(eFile*self,void*cl)
{
	return Py_BuildValue("i",self->fd);
}
static PyObject*File_sechdrs(eFile*self,void*cl)
{
	return Py_BuildValue("O",self->sec_hdrs);
}
static PyObject*File_name(eFile*self,void*cl)
{
	return Py_BuildValue("S",self->fname);
}
// blocking setters
static int File_set(eFile*self,PyObject*val,void*cl)
{
	PyErr_SetString(PyExc_Exception,"Cannot set attribute");
	return -1;
}
// Struct Declarations
static PyMemberDef File_members[] = {
	{"fd",T_INT,offsetof(eFile,fd),0,"file descriptor"},
	{"info",T_INT,offsetof(eFile,info),0,"info"},
//	{"sections",T_OBJECT,offsetof(eFile,sec_hdrs),0,"section headers"},
//	{"fname",T_OBJECT,offsetof(eFile,fname),0,"file name"},
	{NULL}
};
static PyGetSetDef File_getseters[] = {
//	{"fd",(getter)File_fd,(setter)File_set,"file descriptor",NULL},
	{"sections",(getter)File_sechdrs,(setter)File_set,"section headers",NULL},
	{"fname",(getter)File_name,(setter)File_set,"file name",NULL},
	{NULL}
};
static PyMethodDef File_methods[] = {
	{"readfile",(PyCFunction)File_readfile,METH_NOARGS,"reads the ELF file and gets section headers"},
	{"gets",(PyCFunction)File_gets,METH_VARARGS,"gets a string of 'max' len from a memory address"},
	{"geti",(PyCFunction)File_geti,METH_VARARGS,"gets an integer of size 'size' from a memory address"},
	{"dumps",(PyCFunction)File_dumps,METH_O,"dumps the contents of the section"},
	{"decompile",(PyCFunction)File_decompile,METH_O,"decompiles section if EXEC flag is on"},
	{NULL}
};
static PyTypeObject FileType = {
	PyVarObject_HEAD_INIT(NULL,0)
	"elfr.File",	// tp_name
	sizeof(eFile),	// tp_basicsize
	0,	// tp_itemsize
	(destructor)File_dealloc,	// tp_dealloc
	0,	// tp_print
	0,	// tp_getattr
	0,	// tp_setattr
	0,	// tp_compare
	0,	// tp_repr
	0,	// tp_as_number
	0,	// tp_as_seq
	0,	// tp_as_mapping
	0,	// tp_hash
	0,	// tp_call
	0,	// tp_str
	0,	// tp_getattro
	0,	// tp_setattro
	0,	// tp_as_buffer
	Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,	// tp_flags
	"File objects",	// to_doc
	0,	// to_traverse
	0,	// tp_clear
	0,	// tp_rich_compare
	0,	// tp_weaklistoffset
	0,	// to_iter
	0,	// tp_iternext
	File_methods,	// tp_meth
	File_members,	// tp_memb
	File_getseters,	// tp_getset
	0,	// tp_base
	0,	// tp_dict
	0,	// tp_descr_get
	0,	// tp_descr_set
	0,	// to_dictoffset
	(initproc)File_init,	// tp_init
	0,	// tp_alloc
	File_new,	// tp_new
};


//
// Module Specific Stuff
//
static PyMethodDef module_methods[] = {{NULL}};

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initelfr(void)
{
	PyObject*mod;

	if(PyType_Ready(&SecHdrType)<0)
		return;
	if(PyType_Ready(&FileType)<0)
		return;

	mod = Py_InitModule3("elfr",module_methods,"ELF Reader Module");
	if(mod==NULL)
		return;

	Py_INCREF(&SecHdrType);
	PyModule_AddObject(mod,"SecHdr",(PyObject*)&SecHdrType);
	Py_INCREF(&FileType);
	PyModule_AddObject(mod,"File",(PyObject*)&FileType);
}

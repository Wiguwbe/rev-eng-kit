#!/usr/bin/env python
#
# Reverse Engineering Kit
#
# (Tries to) Decompile assembly
# to C source code
#
#
# Copyright Tiago Teixeira, 2018
#
import elfr
import subprocess
import sys

# interaction mode
f = None
code = ''

# constants
# register names
rnames = {
	'rax': ['rax','eax','ax','al','ah'],
	'rcx': ['rcx','ecx','cx','cl','ch'],
	'rdx': ['rdx','edx','dx','dl','dh'],
	'rbx': ['rbx','ebx','bx','bl','bh'],
	'rsp': ['rsp','esp','sp','spl'],
	'rbp': ['rbp','ebp','bp','bpl'],
	'rsi': ['rsi','esi','si','sil'],
	'rdi': ['rdi','edi','di','dil'],
	'rip': ['rip','eip','ip'],
	'r8' : ['r8','r8d','r8w','r8b'],
	'r9' : ['r9','r9d','r9w','r9b'],
	'r10': ['r10','r10d','r10w','r10b'],
	'r11': ['r11','r11d','r11w','r11b'],
	'r12': ['r12','r12d','r12w','r12b'],
	'r13': ['r13','r13d','r13w','r13b'],
	'r14': ['r14','r14d','r14w','r14b'],
	'r15': ['r15','r15d','r15w','r15b']
}
# for IF statements
comparators = {
	'jne'	: '==',
	'je'	: '!=',
	'jge'	: '<',
	'jle'	: '>',
	'jg'	: '<=',
	'jl'	: '>='
}
# the other statements
rcomps = {
	'jne'	: '!=',
	'je'	: '==',
	'jge'	: '>=',
	'jle'	: '<=',
	'jg'	: '>',
	'jl'	: '<'
}

# decode 'objdump' operation
#
# op: line of disassembled instruction
#
# return: [tuple]
# (address,instruction,op1,op2,len)
def decode_op(op):
	# opcode format:
	# ' address:\tbinary...\t<ins> <op1>,<op2>...#comment'
	a = op.split('\t')
	a[0]=a[0][:-1]	# get rid of ':'
	op1 = ''
	op2 = ''
	ins = ''
	c = 0
	l = 0
	ll = a[1].split(' ')
	for v in ll:
		if v!='':
			l+=1
	b = a[2].split(' ')
	ins = b[0]
	for i in range(1,len(b)):
		if b[i]=='':
			continue	# empty
		if ',' in b[i]:
			d=b[i].split(',')
			op1=d[0]
			op2=d[1]
			# there could be more useless ops for there
			break
		# else there is an operand there
		if c==1:
			op2=b[i]
			break
		c+=1
		op1=b[i]
	return (int(a[0],16),ins,op1,op2,l)

# gets register name
# to use in dictionary
def get_rname(rr):
	r=''
	for k in rnames:
		if rr[1:] in rnames[k]:
			r=k
	if r=='':
		print 'No register name??'
	return r

# does some loop / if-else parsing
# and adds some stuff to 'asm' code
# to be able to write loops
#
# asm: the 'objdump' assembly
#
# return: [string]
#	prepared assembly like objdump
#	already without headers
def prepare(asm):
	lines = asm.split('\n')
	if lines[-1]!='':
		lines.append('')	# empty string safety
	i = 0
	ret = ''
	control = []	# IF(1),WHILE(2)
	hvar = []	# keeps strings for recursiveness loop finding
	while not '<main>:' in lines[i]:
		i+=1
	i+=1	# next line
	while lines[i]!='':
		ins = decode_op(lines[i])
		h = ['cmp' in ins[1],'jmp' in ins[1]]
		if not h[0] and not h[1]:
			# check if 'IF'/'ELSE' has ended
			if len(control)!= 0 and control[-1][0]==1:
				if control[-1][1]==ins[0]:	# the jmp/j<cond> target
					# has ended
					if len(hvar)>0:
						hvar[-1]+='}\n'
					else:
						ret+='}\n'
					control.pop()
			if len(hvar)>0:
				hvar[-1]+=lines[i]+'\n'
			else:
				ret+=lines[i]+'\n'
			i+=1
			continue
		# now the hard part
		if h[1]:	# jmp
			if len(control)==0 or control[-1][0]!=1:
				# new FOR/WHILE
				hvar.append('while( TRPL )\n{\n')
				control.append((2,ins[0]+ins[4]))
			else:
				# ELSE
				control.pop()
				control.append((1,int(ins[2],16)))
				if len(hvar)!=0:
					hvar[-1]+='}\nelse\n{\n'
				else:
					ret+='}\nelse\n{\n'
		elif h[0]:	# cmp
			next = decode_op(lines[i+1])
			if int(next[2],16)>ins[0]:
				# IF statement
				c = comparators[next[1]]
				if len(hvar)>0:
					hvar[-1]+='if( '+ins[3]+' '+c+' '+ins[2]+' )\n{\n'
				else:
					ret+='if( '+ins[3]+' '+c+' '+ins[2]+' )\n{\n'
				control.append((1,int(next[2],16)))
			elif len(control)==0 or ( control[-1][0]!=1 and control[-1][1]<int(next[2],16)):
				# DO..WHILE
				tri = ' '+next[2]+':'	# jmp target
				trs = 'do\n{\n'+tri
				s = '}\nwhile( '+ins[3]+' '+rcomps[next[1]]+' '+ins[2]+' );\n'
				if len(hvar)>0:
					hvar[-1]=hvar[-1].replace(tri,trs)
					hvar[-1]+=s
				else:
					ret=ret.replace(tri,trs)
					ret+=s
			else:
				# end WHILE
				# hvar as to be len>0
				control.pop()
				hvar[-1]+='}\n'
				s = ins[3]+' '+rcomps[next[1]]+' '+ins[2]
				tmp = hvar.pop()
				tmp = tmp.replace('TRPL',s);
				if len(hvar)!=0:
					hvar[-1]+=tmp
				else:
					ret+=tmp
			i+=1
		i+=1
		# continue
	return ret

# check registers for arguments
# values
#
# rs: dictionary of registers
#
# return: [string]
#	the 'C'-like code of arguments
def add_args(rs):
	ret = ''
	if rs['rdi']!='':
		ret+=str(rs['rdi'])
	else:
		return ret
	if rs['rsi']!='':
		ret+=','+str(rs['rsi'])
	else:
		return ret
	if rs['rdx']!='':
		ret+=','+str(rs['rdx'])
	else:
		return ret
	if rs['rcx']!='':
		ret+=','+str(rs['rcx'])
	else:
		return ret
	if rs['r8']!='':
		ret+=','+str(rs['r8'])
	else:
		return ret
	if rs['r9']!='':
		ret+=','+str(rs['r9'])
	return ret

# pseudo run program
# keep track of registers values
# such as memory addresses
# when a call* is found
# check a 'database' to find what
# parameters types it takes
# so the stack can start to
# be decoded
# starts execution at 'main'
#
# asm: the 'objdump' assembly
def run(asm):
	inss = asm.split('\n')
	i = 0
	c= ''	# the C code
	# all 'relevant' registers
	rgs = {
		'rip':'',
		'rax':'',
		'rcx':'',
		'rdx':'',
		'rbx':'',
		'rsp':'',
		'rbp':'',
		'rsi':'',
		'rdi':'',
		'r8':'',
		'r9':'',
		'r10':'',
		'r11':'',
		'r12':'',
		'r13':'',
		'r14':'',
		'r15':''
	}
	# start now
	while inss[i]!='':
		# check if it's a prepared statement
		if inss[i][0]!=' ':
			if inss[i][0]=='}' or inss[i][0]=='{' or inss[i]=='do' or inss[i]=='else':
				# ignore, just print
				c += inss[i]+'\n'
				i+=1
				continue
			ops = inss[i].split(' ') # <something>(' '<op1>' '<!=>' '<op2>' ')
			# substitute operands
			o1=''
			o2=''
			if ops[1][0]=='%':
				r1=get_rname(ops[1])
				if r1=='':
					i+=1
					continue
				o1=rgs[r1]
				if ops[3][0]=='%':
					# reg-reg
					r2=get_rname(ops[2])
					if r2=='':
						i+=1
						continue
					o2=rgs[r2]
				elif ops[3][0]=='$':	# possible not
					# reg-imm
					o2=ops[3][1:]
				else:
					# reg-mem
					o2=ops[3]
			elif ops[1][0]=='$':
				o1=ops[1][1:]
				if ops[3][0]=='%':
					# imm-reg
					r1 = get_rname(ops[3])
					if r1=='':
						i+=1
						continue
					o2=rgs[r1]
				elif ops[3][0]=='$':
					# imm-imm	( impossible )
					o2=ops[3][1:]
				else:
					# imm-mem
					o2=ops[3]
			else:
				o1=ops[1]
				if ops[3][0]=='%':
					# mem-reg
					r1 = get_rname(ops[3])
					if r1=='':
						i+=1
						continue
					o2=rgs[r1]
				elif ops[3][0]=='$':
					# mem-imm
					o2=ops[3][1:]
				else:
					# mem-mem
					o2=ops[3]
			c+=ops[0]+o1+ops[2]+o2+ops[4]+'\n'
			i+=1
			continue

		ins = decode_op(inss[i])
		rgs['rip'] = ins[4]+ins[0]

		# IGNORE
		# words to ignore
		if 'leave' in ins[1]:
			i+=1
			continue

		# RETURN
		if 'ret' in ins[1]:
			c += 'return '+rgs['rax']+';\n'
			break

		# check what type of instruction it is
		# MOVE
		if 'mov' in ins[1]:
			if ins[2][0]=='%':
				if ins[3][0]=='%':
					# reg->reg
					r1=get_rname(ins[2])
					r2=get_rname(ins[3])
					if r1=='' or r2=="":
						i+=1
						continue
					rgs[r2]=rgs[r1]
				else:
					# reg->mem
					r1=get_rname(ins[2])
					if r1=='':
						i+=1
						continue
					c+=ins[3]+' = '+str(rgs[r1])+';\n'
			elif ins[2][0]=='$':
				if ins[3][0]=='%':
					# imm->reg
					r1=get_rname(ins[3])
					if r1=='':
						i+=1
						continue
					rgs[r1]=ins[2][1:]
				else:
					# imm->mem
					c+=ins[3]+' = '+ins[2][1:]+';\n'
			else:
				if ins[3][0]=='%':
					# mem->reg
					r1=get_rname(ins[3])
					if r1=='':
						i+=1
						continue
					rgs[r1]=ins[2]
				else:
					# mem->mem (impossible?)
					c+=ins[3]+' = '+ins[2]+';\n'
			i+=1
			continue

		# POINTERS
		if 'lea' in ins[1]:
			# assume only mem to reg/mem
			# assume <imm>(%reg),<dest>
			aa = ins[2].split('(')
			aa[0]=aa[0][2:]	# ignore '0x'
			aa[1]=aa[1][:-1]	# ignore '%' and ')'
			r1 = get_rname(aa[1])
			r2 = get_rname(ins[3])
			if r1=='' or r2=="":
				print r1+' '+r2
				i+=1
				continue
			v = int(aa[0],16)
			ad = 0
			if r1=='rip':
				ad=v+ins[4]+ins[0]
			else:
				ad=v+rgs[r1]
			rgs[r2]=ad

		# ARITHMETIC
		if 'add' in ins[1] or 'sub' in ins[1] or 'mul' in ins[1] or 'div' in ins[1] or 'and' in ins[1] or 'xor' in ins[1] or 'or' in ins[1][0:2] or 'shl' in ins[1] or 'shr' in ins[1] or 'sar' in ins[1] or 'sal' in ins[1]:
			# op2 <sig>= op1
			sig = ''
			if 'add' in ins[1]:
				sig='+'
			elif 'sub' in ins[1]:
				sig='-'
			elif 'mul' in ins[1]:
				sig='*'
			elif 'div' in ins[1]:
				sig='/'
			elif 'and' in ins[1]:
				sig='&'
			elif 'xor' in ins[1]:
				sig='^'
			elif 'shl' in ins[1] or 'sal' in ins[1]:
				sig='<<'
			elif 'sar' in ins[1] or 'shr' in ins[1]:
				sig='>>'
			else:	# or
				sig='|'
			if ins[2][0]=='%':
				if ins[3][0]=='%':
					# reg->reg
					r1=get_rname(ins[2])
					r2=get_rname(ins[3])
					if r1=='' or r2=="":
						i+=1
						continue
					rgs[r2]='('+rgs[r2]+')'+sig+rgs[r1]
				else:
					# reg->mem
					r1=get_rname(ins[2])
					if r1=='':
						i+=1
						continue
					c+=ins[3]+' '+sig+'= '+rgs[r1]+';\n'
			elif ins[2][0]=='$':
				if ins[3][0]=='%':
					# imm->reg
					r1=get_rname(ins[3])
					if r1=='':
						i+=1
						continue
					rgs[r1]='('+str(rgs[r1])+')'+sig+ins[2][1:]
				else:
					# imm->mem
					c+=ins[3]+' '+sig+'= '+ins[2][1:]+';\n'
			else:
				if ins[3][0]=='%':
					# mem->reg
					r1=get_rname(ins[3])
					if r1=='':
						i+=1
						continue
					rgs[r1]='('+rgs[r1]+')'+sig+ins[2]
				else:
					# mem->mem
					c+=ins[3]+' '+sig+'= '+ins[2]+';\n'
			i+=1
			continue

		# CALL / FUNCTION
		if 'call' in ins[1]:
			# Possible only print 'foo(params)' ...
			#
			# ins[3] should have the name of the function
			foo = ''
			if ins[3]!='':
				foo = ins[3].split('@')[0][1:]	# '<foo@plt>'
			else:
				foo=ins[2]	# the address
			# how to find the number of params ?
			# maybe prompt the user ?
			c+=str(foo)+'('+add_args(rgs)+');\n'
		i+=1
	return c

# ident and finalize C code
# still with mem values and stuff
# but fuck the user...
#
# code: the C code
#
# return: [string]
#	idented C code
def ident(code):
	ret = 'int main()\n{\n'
	lines = code.split('\n')
	tabs = 1
	for i in range(len(lines)):
		if lines[i]=='':
			break
		if lines[i]=='}':
			tabs-=1
		ret += ('\t'*tabs)+lines[i]+'\n'
		if lines[i]=='{':
			tabs+=1
	ret += '}\n'
	return ret

def main(exe):
	global f
	global code
	try:
		f = elfr.File(exe)
		f.readfile()
		sec = f.sections
		exs = []
		sname = ''
		for s in sec:
			if s.is_exec():
				exs.append(s.name)
	except:
		print 'Failed to read file'
		exit(2)

	out = ''
	if '.text' in exs:
		out = f.decompile('.text')
	else:
		for e in exs:
			t = f.decompile(e)
			if '<main>:' in t:
				out = t
				break


	pre = prepare(out)
	dec = run(pre)
	code= ident(dec)

	print code


if __name__=='__main__':
	if len(sys.argv)!=2:
		print 'usage: %s <exe file>' % sys.argv[0]
		exit(1)
	main(sys.argv[1])


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
	if len(a)<3:
		return None
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
#		print 'No register name??\t['+rr+']'
		pass
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
	start=i
	while lines[i]!='':
		i+=1
	end=i
	restart = True
	# iterate through the function until there are no more loops
	while restart:
		restart=False
		# show the state DEBUG
#		for i in range(start,end):
#			print lines[i]
#		print '-----------------'
		for i in range(start,end):
			if lines[i][0]!=' ':
				continue
			op = decode_op(lines[i])
			if op==None:
				lines.pop(i)
				i-=1
				end-=1
				continue
			if 'cmp' in op[1]:
				restart=True
				# if or do..while
				next = decode_op(lines[i+1])
				j = int(next[2],16)
				if j>op[0]:
					# IF/ELSE
					# replace both lines
					lines[i] = 'if( '+op[2]+' '+comparators[next[1]]+' '+op[3]+' )'
					lines[i+1] = '{'
					# find the ELSE statement
					for ii in range(i+2,end):
						if lines[ii][0]!=' ':
							continue
						# looking for a <jmp> or the target of 'j'
						p = decode_op(lines[ii])
						if p[0]==j:
							# single IF
							lines.insert(ii,'}')
							end+=1
							break;
						n = decode_op(lines[ii+1])
						if n[0]==j and 'jmp' in p[1]:
							# if/ELSE
							j2 = int(p[2],16)
							lines[ii]='}\nelse\n{'
							# find the end of the else
							for iii in range(ii+2,end):
								if lines[iii][0]!=' ':
									continue
								o = decode_op(lines[iii])
								if o[0]==j2:
									# found it
									lines.insert(iii,'}')
									end+=1
									break
							break
				else:
					# DO..WHILE
					# replace lines
					lines[i] = '}'
					lines[i+1]='while( '+op[3]+' '+rcomps[next[1]]+' '+op[2]+' );'
					# find the start of it
					for ii in range(start,i):
						if lines[ii][0]!=' ':
							continue
						p = decode_op(lines[ii])
						if p[0]==j:
							# found it
							lines.insert(ii,'do\n{')
							end+=1
							break
				break	# 'end' changed
			if 'jmp' in op[1]:
				# WHILE
				restart=True
				print 'FOUND a WHILE'
				next = decode_op(lines[i+1])
				j = int(op[2],16)
				# find the end of it
				for ii in range(i+1,end):
					if lines[ii][0]!=' ':
						continue
					p = decode_op(lines[ii])
					if p[0]==j:
						# found the end
						n = decode_op(lines[ii+1])
						j2 = int(n[2],16)
						# do it already
						lines[i] = 'while( '+p[3]+' '+rcomps[n[1]]+' '+p[2]+' )\n{'
						if j2!=next[0]:
							# NESTED LOOPS !
							nest = [j2]
							# replace already
							lines.pop(ii)
							lines[ii]='}'
							end-=1	# popped
							# makes no difference ( i hope ? )
							while len(nest)>0:
								for iii in range(i+len(nest),ii):
									if lines[iii][0]!=' ':
										continue
									# find the target
									o = decode_op(lines[iii])
									if o[0]==nest[-1]:
										# found the target
										s = decode_op(lines[iii+1])
										j3 = int(s[2],16)
										lines.pop(iii)	# delete cmp
										lines[iii] = '}' # replace 'j'
										# always insert at ( i+1 )
										lines.insert(i+1,'while( '+o[3]+' '+rcomps[s[1]]+' '+o[2]+' )\n{')
										# end keeps its value
										if j3==next[0]:
											# last nested loop
											nest.pop()	# delete last entry
										else:
											# another nested loop
											nest.append(j3)
										break
						else:
							# simple WHILE
							# nothing more to add
						#	end-=1
							pass
						break
				break	# from the beggining
	# all done
	# build final string
	for i in range(start,end):
		ret+=lines[i]+'\n'
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
	foo = False	# to check if function has been called, useful when there is no return code
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
						rgs[r2]=ins[2]
						i+=1
						continue
					if r1=='rax' and foo:
						foo=False
						c+=rgs['rax']+';\n'
					rgs[r2]=rgs[r1]
				else:
					# reg->mem
					r1=get_rname(ins[2])
					if r1=='':
						i+=1
						continue
					if r1=='rax' and foo:
						foo=False
					c+=ins[3]+' = '+str(rgs[r1])+';\n'
			elif ins[2][0]=='$':
				if ins[3][0]=='%':
					# imm->reg
					r1=get_rname(ins[3])
					if r1=='':
						i+=1
						continue
					if r1=='rax' and foo:
						foo=False
						c+=rgs['rax']+';\n'
					rgs[r1]=ins[2][1:]
				else:
					# imm->mem
					t = ins[3]
					r = get_rname(ins[3].split('(')[1][:-1])
					if r!=''  and r!="rbp":
						t=rgs[r]
					c+=t+' = '+ins[2][1:]+';\n'
			else:
				if ins[3][0]=='%':
					# mem->reg
					r1=get_rname(ins[3])
					if r1=='':
						i+=1
						continue
					if r1=='rax' and foo:
						foo=False
						c+=rgs['rax']+';\n'
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
			aa[0]=aa[0][aa[0].index('x')+1:]	# ignore '0x'
			aa[1]=aa[1][:-1]	# ignore ')'
			r1 = get_rname(aa[1])
			r2 = get_rname(ins[3])
			if r1=='' or r2=="":
				print '['+str(ins[0])+']\t'+r1+' '+r2
				i+=1
				continue
			v = int(aa[0],16)
			ad = 0
			if r1=='rip':
				ad=v+ins[4]+ins[0]
			else:
				try:
					ad=hex(v+rgs[r1])
				except:
					ad = ins[2]
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
			# %rax will have the output of it
			foo = ''
			if ins[3]!='':
				foo = ins[3].split('@')[0][1:]	# '<foo@plt>'
			else:
				foo=ins[2]	# the address
			# how to find the number of params ?
			# maybe prompt the user ?
			rgs['rax']=str(foo)+'('+add_args(rgs)+')'
			foo = True
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
#	print pre
	dec = run(pre)
#	print '-------------------------------'
#	print dec
	code= ident(dec)

#	print '-------------------------------'
	print code


if __name__=='__main__':
	if len(sys.argv)!=2:
		print 'usage: %s <exe file>' % sys.argv[0]
		exit(1)
	main(sys.argv[1])


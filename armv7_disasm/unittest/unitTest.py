#!/usr/bin/env python

# requires the armv7_disasm.XXX shared object
# try `make armv7_disasm.dylib` or `make armv7_disasm.so` depending your paltform

import re
import os, sys, subprocess
import struct
from ctypes import *
from capstone import *
import test
import platform

disasmBuff = create_string_buffer(2048)
instBuff =   create_string_buffer(2048)

library = "armv7_disasm"
if platform.system() == "Linux":
	library += ".so"
elif platform.system() == "Windows":
	library += ".dll"
elif platform.system() == "Darwin":
	library += ".dylib"

binja = CDLL(library)
md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
def disassemble_binja(insvalue, baseAddress):
	for a in range(len(disasmBuff)):
		disasmBuff[a] = b'\0'
	for a in range(len(instBuff)):
		instBuff[a] = b'\0'

	err = binja.armv7_decompose(insvalue, instBuff, baseAddress, False)
	if err == 1:
		return "decomposer failed"
	elif err == 2:
		return "group decomposition failed"
	elif err == 3:
		return "unimplemented"
	elif err == 4:
		return "disassembler failed"

	if binja.armv7_disassemble(instBuff, disasmBuff, 2048) == 0:
		return disasmBuff.value.decode('utf-8')

	return "disassembly failed"

def disassemble_capstone(insvalue, baseAddress):
	insbytes = struct.pack('<I', insvalue)
	for a in md.disasm(insbytes, baseAddress):
		return a.mnemonic + "\t" + a.op_str

def normalizeNumeric(numeric):
	if numeric.startswith("0x"):
		numeric = numeric[2:]
	if numeric.startswith("#"):
		numeric = numeric[1:]
	else:
		return numeric

	if numeric == "0" or numeric == "0.000000":
		return "0"

	neg = False
	if numeric.startswith("-"):
		neg = True
		numeric = numeric[1:]

	if numeric.find(".") != -1:
		numeric = float(numeric)
		return numeric
	elif numeric.startswith("0x"):
		numeric = int(numeric,16)
	else:
		try:
			numeric = int(numeric,10)
		except:
			return numeric

	if neg:
		return hex((-numeric + (1 << 32)) % (1 << 32))

	return hex((numeric + (1 << 32)) % (1 << 32))

def areEqual(binja, capstone):
	capstone = capstone.strip()
	if binja == capstone:
		return True
	
	belms = re.findall(r"[^ \]\[,\t\{\}]+", binja)
	celms = re.findall(r"[^ \]\[,\t\{\}]+", capstone)

	#Capstone's rfe instruction is compeltely broken
	if celms[0].startswith("rfe") and belms[0] == celms[0]:
		return True
	#check for adr alias missing in capstone
	extension = ("vrintm", "vrintn", "vrinta", "vrintp", "vmaxnm", "vselvs", "vminnm", "vcvtp", "vcvtn", "vsel", "vcvtm", "vcvta")
	for a in extension:
		if celms[0].startswith(a) and belms[0] == "cdp2":
			return True

	for i,a in enumerate(celms):
		celms[i] = normalizeNumeric(a)
	for i,a in enumerate(belms):
		belms[i] = normalizeNumeric(a)

	def tohex(val, nbits):
		  return hex((val + (1 << nbits)) % (1 << nbits))

	if len(belms) > 1 and belms[0] == "cpsie" and len(celms) > 1 and celms[1] == "none":
		del(celms[1])
	belms[0] = belms[0].replace(".", "")
	celms[0] = celms[0].replace(".", "")

	blastelm = -1
	clastelm = -1
	if belms[blastelm] == "!":
		blastelm = -2
	if celms[clastelm] == "!":
		clastelm = -2
	if len(celms) >= 3 and len(belms) >= 2 and celms[clastelm-1] == "pc":
		try:
			#print(hex(int(celms[-1]) + baseAddress + 8))
			#print(hex(int(belms[-1])))
			if int(belms[blastelm]) == (int(celms[clastelm]) + baseAddress + 8):
				return True
		except:
			pass

	for a,b in zip(belms, celms):
		if b != a:
			#print("celms: ", celms)
			#print("belms: ", belms)
			return False
	return True
				
usage = "%s [-v] [-f <armv7File>] [-b] [-u <unitTestFile>] [<32-bitValue>]" % sys.argv[0]
def main():
	if len(sys.argv) < 2:
		print(usage)
		return

	instructions = []
	verbose = 0
	if sys.argv[1] == "-v":
		verbose = 1
		sys.argv = sys.argv[1:]
	if sys.argv[1] == "-vv":
		verbose = 2
		sys.argv = sys.argv[1:]
	if sys.argv[1] == "-v8":
		md = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_V8)
		sys.argv = sys.argv[1:]

	disasmOnly = False
	brute = False
	if sys.argv[1] == "-f":
		if len(sys.argv) < 3:
			print(usage)
			return
		tmp = open(sys.argv[2]).read()	
		if len(tmp) % 4 != 0:
			print("File must be multiple of 4")
			return
		for a in range(0, len(tmp), 4):
			instructions.append(tmp[a:a+4])
	elif sys.argv[1] == "-t":
		for a in test.tests:
			instructions.extend(struct.pack("<L",a))
	elif sys.argv[1] == "-u":
		lines = open(sys.argv[2]).read().split("\n")
		for line in lines:
			if line.startswith("#") or len(line) == 0:
				continue
			print(line)
			hexvalues, disasm = line.split(" = ")
			instructions.append(int(hexvalues, 16))
	elif sys.argv[1] == "-b":
		brute = True
	elif sys.argv[1] == "-d":
		disasmOnly = True
		tmp = open(sys.argv[2]).read()	
		if len(tmp) % 4 != 0:
			print("File must be multiple of 4")
			return
		for a in range(0, len(tmp), 4):
			instructions.append(tmp[a:a+4])
	else:
		try:
			instructions.append(struct.pack("<L",int(sys.argv[1], 16)))
		except:
			print("Failed to parse 32-bit hex value %s" % sys.argv[1])
			return

	if disasmOnly:
		offset = 0
		for instruction in instructions:
			binja = disassemble_binja(instruction, offset)
			print(" %x:\t%s\t%s" % (offset, instruction[::-1].encode('hex'), binja))
			offset += 4
		sys.exit()

	import random
	random.seed(3)
	#f = open('errors.bin', 'w')
	errors = 0
	success = 0
	if brute:
		total = 1000000
		for a in range(total):
			instruction = struct.pack("<L", random.randint(0, 0xffffffff))
			binja = disassemble_binja(instruction, 0x08040000)
			capstone = disassemble_capstone(instruction, 0x08040000)
			if (binja is not None and capstone is not None and not areEqual(binja, capstone)):
				if "UNDEFINED" in binja or "failed" in binja:
					if capstone is not None:
						opcode = capstone.split('\t')[0]
						print("ERROR: Oracle: %s '%s'\n You: %s '%s'" % (instruction.encode('hex'), capstone, instruction.encode('hex'), binja))
						#f.write(instruction)
						errors += 1
				else:
					try:
						print("ERROR: Oracle: %s '%s'\n You: %s '%s'" % (instruction.encode('hex'), capstone, instruction.encode('hex'), binja))
					except:
						print(repr(capstone))
						print(repr(binja))
					#f.write(instruction)
					errors += 1
			else:
				success += 1
		print("errors: %d/%d success percentage %%%.2f" % (errors, total, (float(success)/float(total)) * 100.0))
		sys.exit()

	undefined = {}
	for instruction in instructions:
		binja = disassemble_binja(instruction, 0x08040000)
		capstone = disassemble_capstone(instruction, 0x08040000)
		if verbose > 1:
			print("binja:", binja)
			print("capst:", capstone)
		if binja == "unimplemented":
			if capstone is not None:
				opcode = capstone.split('\t')[0]
				opcode = opcode.split('.')[0]
				if opcode not in undefined.keys():
					undefined[opcode] = 1
				else:
					undefined[opcode] += 1
			continue
		if (binja is not None and capstone is not None and not areEqual(binja, capstone)):
			if "UNDEFINED" in binja or "failed" in binja:
				if capstone is not None:
					opcode = capstone.split('\t')[0]
					if opcode not in undefined.keys():
						undefined[opcode] = 1
					else:
						undefined[opcode] += 1
					errors += 1
					print("ERROR: Oracle: %08X '%s'\n            You: %08X '%s'" % (instruction, capstone, instruction, binja))
					#f.write(instruction)
			else:
				print("ERROR: Oracle: %08X '%s'\n          You: %08X '%s'" % (instruction, capstone, instruction, binja))
				errors += 1
				#f.write(instruction)
		else:
			success += 1
	print("%d errors, %d successes, %d test cases success percentage %%%.2f" % (errors, success, len(instructions), (float(success)/float(len(instructions))) * 100.0))

	print("%d undefined instructions" % len(undefined))
	if verbose:
		import operator
		sorted_undefined = sorted(undefined.items(), key=operator.itemgetter(1))
		for a,b in sorted_undefined:
			print("%s\t%d" % (a, b))

if __name__ == "__main__":
	main()

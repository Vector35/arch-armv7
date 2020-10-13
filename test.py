#!/usr/bin/env python

test_cases = [
	(b'\x00\xf0\x20\xe3', ''), # nop, gets optimized from function
]

import sys
import binaryninja
from binaryninja import core
from binaryninja import binaryview
from binaryninja import lowlevelil

def il2str(il):
	if isinstance(il, lowlevelil.LowLevelILInstruction):
		return '%s(%s)' % (il.operation.name, ','.join([il2str(o) for o in il.operands]))
	else:
		return str(il)

# TODO: make this less hacky
def instr_to_il(data):
	platform = binaryninja.Platform['linux-armv7']
	# make a pretend function that returns
	bv = binaryview.BinaryView.new(data)
	bv.add_function(0, plat=platform)
	assert len(bv.functions) == 1

	result = []
	for block in bv.functions[0].low_level_il:
		for il in block:
			result.append(il2str(il))
	result = '; '.join(result)
	assert result.endswith('LLIL_UNDEF()')
	result = result[0:result.index('LLIL_UNDEF()')]
	if result.endswith('; '):
		result = result[0:-2]

	return result

if __name__ == '__main__':
	for (test_i, (data, expected)) in enumerate(test_cases):
		actual = instr_to_il(data)
		if actual != expected:
			print('MISMATCH AT TEST %d!' % test_i)
			print('\t   input: %s' % data.hex())
			print('\texpected: %s' % expected)
			print('\t  actual: %s' % actual)
			sys.exit(-1)

	print('success!')
	sys.exit(0)

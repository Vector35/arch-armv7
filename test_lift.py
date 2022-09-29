#!/usr/bin/env python

test_cases = \
[
    # ror r0, r1
    ('linux-armv7', b'\x70\x01\xa0\xe1', 'LLIL_SET_REG.d(r0,LLIL_ROR.d(LLIL_REG.d(r0),LLIL_AND.b(LLIL_REG.d(r1),LLIL_CONST.b(0xFF))))'),
    # ror r0, 7
    ('linux-armv7', b'\xe0\x03\xa0\xe1', 'LLIL_SET_REG.d(r0,LLIL_ROR.d(LLIL_REG.d(r0),LLIL_AND.b(LLIL_CONST.d(0x7),LLIL_CONST.b(0xFF))))'),
    # rors r0, r1
    ('linux-armv7', b'\x70\x01\xb0\xe1', 'LLIL_SET_REG.d(r0,LLIL_ROR.d{*}(LLIL_REG.d(r0),LLIL_AND.b(LLIL_REG.d(r1),LLIL_CONST.b(0xFF))))'),
    # rors r0, 7
    ('linux-armv7', b'\xe0\x03\xb0\xe1', 'LLIL_SET_REG.d(r0,LLIL_ROR.d{*}(LLIL_REG.d(r0),LLIL_AND.b(LLIL_CONST.d(0x7),LLIL_CONST.b(0xFF))))'),
    # vadd.f32 s0, s1, s2
    ('linux-armv7', b'\x81\x0a\x30\xee', 'LLIL_SET_REG.d(s0,LLIL_FADD.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))'),
    # vsub.f32 s0, s1, s2
    ('linux-armv7', b'\xc1\x0a\x30\xee', 'LLIL_SET_REG.d(s0,LLIL_FSUB.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))'),
    # vmul.f32 s0, s1, s2
    ('linux-armv7', b'\x81\x0a\x20\xee', 'LLIL_SET_REG.d(s0,LLIL_FMUL.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))'),
    # vdiv.f32 s0, s1, s2
    ('linux-armv7', b'\x81\x0a\x80\xee', 'LLIL_SET_REG.d(s0,LLIL_FDIV.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))'),
    # svc #0
    # svc #1
    # svc #2
    # svc #3
    ('linux-armv7', b'\x00\x00\x00\xef', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x0)); LLIL_SYSCALL()'),
    ('linux-armv7', b'\x01\x00\x00\xef', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x1)); LLIL_SYSCALL()'),
    ('linux-armv7', b'\x02\x00\x00\xef', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x2)); LLIL_SYSCALL()'),
    ('linux-armv7', b'\x03\x00\x00\xef', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x3)); LLIL_SYSCALL()'),
    # svcle #0xDEAD
    ('linux-armv7', b'\xAD\xDE\x00\xdf', 'LLIL_IF(LLIL_FLAG_COND(LowLevelILFlagCondition.LLFC_SLE,None),1,4); LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0xDEAD)); LLIL_SYSCALL(); LLIL_GOTO(4)'),
    # svcgt #0xdead
    ('linux-armv7', b'\xad\xde\x00\xcf', 'LLIL_IF(LLIL_FLAG_COND(LowLevelILFlagCondition.LLFC_SGT,None),1,4); LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0xDEAD)); LLIL_SYSCALL(); LLIL_GOTO(4)'),
    # mov r0, r1
    ('linux-armv7', b'\x01\x00\xa0\xe1', 'LLIL_SET_REG.d(r0,LLIL_REG.d(r1))'),
    # nop
    ('linux-armv7', b'\x00\xf0\x20\xe3', 'LLIL_NOP()'),
    # vmov.i32 d16, #0
    ('linux-armv7', b'\x10\x00\xc0\xf2', 'LLIL_SET_REG.q(d16,LLIL_CONST.q(0x0))'),
    # vmov.i32 q8, #0
    ('linux-armv7', b'\x50\x00\xc0\xf2', 'LLIL_SET_REG.o(q8,LLIL_OR.o(LLIL_CONST.q(0x0),LLIL_LSL.o(LLIL_CONST.q(0x0),LLIL_CONST.q(0x40))))'),
    # vmov.i32 d16, #1
    ('linux-armv7', b'\x11\x00\xc0\xf2', 'LLIL_SET_REG.q(d16,LLIL_CONST.q(0x100000001))'),
    # vmov.i32 q8, #1
    ('linux-armv7', b'\x51\x00\xc0\xf2', 'LLIL_SET_REG.o(q8,LLIL_OR.o(LLIL_CONST.q(0x100000001),LLIL_LSL.o(LLIL_CONST.q(0x100000001),LLIL_CONST.q(0x40))))'),
    # vmov.i16 d16, #0
    ('linux-armv7', b'\x10\x08\xc0\xf2', 'LLIL_SET_REG.q(d16,LLIL_CONST.q(0x0))'),
    # vmov.i16 d16, #1
    ('linux-armv7', b'\x11\x08\xc0\xf2', 'LLIL_SET_REG.q(d16,LLIL_CONST.q(0x1000100010001))'),
    # vmov.i8 d16, #1
    ('linux-armv7', b'\x11\x0e\xc0\xf2', 'LLIL_SET_REG.q(d16,LLIL_CONST.q(0x101010101010101))'),
    # vmov.i8 q8, #1
    ('linux-armv7', b'\x51\x0e\xc0\xf2', 'LLIL_SET_REG.o(q8,LLIL_OR.o(LLIL_CONST.q(0x101010101010101),LLIL_LSL.o(LLIL_CONST.q(0x101010101010101),LLIL_CONST.q(0x40))))'),
    # vstr s0, [r3, #0x8]
    ('linux-armv7', b'\x02\x0a\x83\xed', 'LLIL_STORE.d(LLIL_ADD.d(LLIL_REG.d(r3),LLIL_CONST.d(0x8)),LLIL_REG.d(s0))'),
    # vstr d16, [r3, #0x8]
    ('linux-armv7', b'\x02\x0b\xc3\xed', 'LLIL_STORE.q(LLIL_ADD.d(LLIL_REG.d(r3),LLIL_CONST.d(0x8)),LLIL_REG.q(d16))'),
    # mov r2, r0
    ('linux-thumb2', b'\x02\x46', 'LLIL_SET_REG.d(r2,LLIL_REG.d(r0))'),
    # cmp r1, r2
    ('linux-thumb2', b'\x91\x42', 'LLIL_SUB.d{*}(LLIL_REG.d(r1),LLIL_REG.d(r2))'),
    # cmp r1, r2, lsl #7
    ('linux-thumb2', b'\xb1\xeb\xc2\x1f', 'LLIL_SUB.d{*}(LLIL_REG.d(r1),LLIL_LSL.d(LLIL_REG.d(r2),LLIL_CONST.d(0x7)))'),
]

import re
import sys
import binaryninja
from binaryninja import binaryview
from binaryninja import lowlevelil
from binaryninja.enums import LowLevelILOperation

def il2str(il):
    sz_lookup = {1:'.b', 2:'.w', 4:'.d', 8:'.q', 16:'.o'}
    if isinstance(il, lowlevelil.LowLevelILInstruction):
        size_code = sz_lookup.get(il.size, '?') if il.size else ''
        flags_code = '' if not hasattr(il, 'flags') or not il.flags else '{%s}'%il.flags

        # print size-specified IL constants in hex
        if il.operation in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR] and il.size:
            tmp = il.operands[0]
            if tmp < 0: tmp = (1<<(il.size*8))+tmp
            tmp = '0x%X' % tmp if il.size else '%d' % il.size
            return 'LLIL_CONST%s(%s)' % (size_code, tmp)
        else:
            return '%s%s%s(%s)' % (il.operation.name, size_code, flags_code, ','.join([il2str(o) for o in il.operands]))
    elif isinstance(il, list):
        return '[' + ','.join([il2str(x) for x in il]) + ']'
    else:
        return str(il)

# TODO: make this less hacky
def instr_to_il(data, platform):
    RETURN = b'\x0e\xf0\xa0\xe1' # mov pc, lr
    if platform == 'linux-thumb2':
        RETURN = b'\xf7\x46'
    RETURN_LIFTED = 'LLIL_JUMP(LLIL_REG.d(lr))'

    platform = binaryninja.Platform[platform]
    # make a pretend function that returns
    bv = binaryview.BinaryView.new(data + RETURN)
    bv.add_function(0, plat=platform)
    assert len(bv.functions) == 1

    result = []
    #for block in bv.functions[0].low_level_il:
    for block in bv.functions[0].lifted_il:
        for il in block:
            result.append(il2str(il))
    result = '; '.join(result)
    # strip return fence
    if result.endswith(RETURN_LIFTED):
        result = result[0:result.index(RETURN_LIFTED)]
    # strip trailing separator
    if result.endswith('; '):
        result = result[0:-2]

    return result

def il_str_to_tree(ilstr):
    result = ''
    depth = 0
    for c in ilstr:
        if c == '(':
            result += '\n'
            depth += 1
            result += '    '*depth
        elif c == ')':
            depth -= 1
        elif c == ',':
            result += '\n'
            result += '    '*depth
            pass
        else:
            result += c
    return result

def test_all():
    for (test_i, (platform, data, expected)) in enumerate(test_cases):
        actual = instr_to_il(data, platform)
        if actual != expected:
            print('MISMATCH AT TEST %d!' % test_i)
            print('\t   input: %s' % data.hex())
            print('\texpected: %s' % expected)
            print('\t  actual: %s' % actual)
            print('\t    tree:')
            print(il_str_to_tree(actual))

            return False

    return True

if __name__ == '__main__':
    if test_all():
        print('success!')
        sys.exit(0)
    else:
        sys.exit(-1)

if __name__ == 'test_lift':
    #if test_all():
    #    print('success!')
    pass

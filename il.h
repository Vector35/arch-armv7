#pragma once

#include "binaryninjaapi.h"
#include "armv7.h"

#define IL_FLAG_N 0
#define IL_FLAG_Z 2
#define IL_FLAG_C 4
#define IL_FLAG_V 6
#define IL_FLAG_Q 8

#define IL_FLAGWRITE_NONE 0
#define IL_FLAGWRITE_ALL 1

struct decomp_result;

bool GetLowLevelILForArmInstruction(BinaryNinja::Architecture* arch, uint64_t addr,
    BinaryNinja::LowLevelILFunction& il, armv7::Instruction& instr, size_t addrSize);
bool GetLowLevelILForThumbInstruction(BinaryNinja::Architecture* arch,
    BinaryNinja::LowLevelILFunction& il, decomp_result *instr, bool ifThenBlock = false);
void SetupThumbConditionalInstructionIL(BinaryNinja::LowLevelILFunction& il, BinaryNinja::LowLevelILLabel& trueLabel,
    BinaryNinja::LowLevelILLabel& falseLabel, uint32_t cond);
BinaryNinja::ExprId GetCondition(BinaryNinja::LowLevelILFunction& il, armv7::Condition cond);

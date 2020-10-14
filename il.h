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

enum Armv7Intrinsic : uint32_t
{
	ARMV7_INTRIN_DBG,
	ARMV7_INTRIN_DMB_SY,
	ARMV7_INTRIN_DMB_ST,
	ARMV7_INTRIN_DMB_ISH,
	ARMV7_INTRIN_DMB_ISHST,
	ARMV7_INTRIN_DMB_NSH,
	ARMV7_INTRIN_DMB_NSHST,
	ARMV7_INTRIN_DMB_OSH,
	ARMV7_INTRIN_DMB_OSHST,
	ARMV7_INTRIN_DSB_SY,
	ARMV7_INTRIN_DSB_ST,
	ARMV7_INTRIN_DSB_ISH,
	ARMV7_INTRIN_DSB_ISHST,
	ARMV7_INTRIN_DSB_NSH,
	ARMV7_INTRIN_DSB_NSHST,
	ARMV7_INTRIN_DSB_OSH,
	ARMV7_INTRIN_DSB_OSHST,
	ARMV7_INTRIN_ISB,
	ARMV7_INTRIN_MRS,
	ARMV7_INTRIN_MSR,
	ARMV7_INTRIN_SEV,
	ARMV7_INTRIN_WFE,
	ARMV7_INTRIN_WFI,
};

bool GetLowLevelILForArmInstruction(BinaryNinja::Architecture* arch, uint64_t addr,
    BinaryNinja::LowLevelILFunction& il, armv7::Instruction& instr, size_t addrSize);
bool GetLowLevelILForThumbInstruction(BinaryNinja::Architecture* arch,
    BinaryNinja::LowLevelILFunction& il, decomp_result *instr, bool ifThenBlock = false);
void SetupThumbConditionalInstructionIL(BinaryNinja::LowLevelILFunction& il, BinaryNinja::LowLevelILLabel& trueLabel,
    BinaryNinja::LowLevelILLabel& falseLabel, uint32_t cond);
BinaryNinja::ExprId GetCondition(BinaryNinja::LowLevelILFunction& il, armv7::Condition cond);

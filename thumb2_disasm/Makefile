CPPFLAGS = 

#
# debug stuff
#

# DEBUG_BUILD - files are compiled with debugging info, no optimizations (if you want to attach debugger)
# DEBUG_DECOMP - code included to print decomposition/decode debugging info
# DEBUG_DISASM - code included to print disassembling debugging info
DEBUG_ALL ?=
ifneq ($(DEBUG_ALL),)
DEBUG_BUILD = 1
DEBUG_DECOMP = 1
DEBUG_DISASM = 1
endif

DEBUG_BUILD ?=
ifneq ($(DEBUG_BUILD),)
$(info DEBUG_BUILD is on!)
CPPFLAGS += -g -O0 -DDEBUG_BUILD
else
CPPFLAGS += -O3
endif

DEBUG_DECOMP ?=
ifneq ($(DEBUG_DECOMP),)
$(info DEBUG_DECOMP is on!)
CPPFLAGS += -DDEBUG_DECOMP
endif

DEBUG_DISASM ?=
ifneq ($(DEBUG_DISASM),)
$(info DEBUG_DISASM is on!)
CPPFLAGS += -DDEBUG_DISASM
endif

CPPFLAGS += -I/usr/local/include -I../armv7 -std=c++11

all: spec.cpp

spec.cpp: generator.py ./arm_pcode_parser/codegencpp.py spec.txt
	./generator.py spec.txt

forcegen:
	echo '' > spec.cpp
	./generator.py spec.txt

#
# generated stuff 
#
clean:
	rm *.o *.dylib
	rm -rf test.dSYM
	rm test


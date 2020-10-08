/* compile using the Makefile
	run with `time ./speedtest`
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include "armv7.h"

int main()
{
	Instruction inst;
	for (size_t i = 0; i < 0xffffffff; i++)
	{
		memset(&inst, 0, sizeof(inst));
		armv7_decompose((uint32_t)i, &inst, 0, 0);
	}
	return 0;
}

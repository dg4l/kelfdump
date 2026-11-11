IOP_BIN = kelfdump.irx
IOP_OBJS = kelfdump.o imports.o
IOP_CFLAGS = -Wunused -Wunused-parameter

all: $(IOP_BIN)

clean:
	rm -rf $(IOP_BIN) *.elf obj

include $(PS2SDK)/Defs.make
include $(PS2SDK)/samples/Makefile.pref
include $(PS2SDK)/samples/Makefile.iopglobal

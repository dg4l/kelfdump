IRX = sio2man padman iomanX fileXio usbd bdm bdmfs_fatfs usbmass_bd kelfdump

EE_BIN = kelfdump.elf
EE_OBJS = ee/main.o ee/erom.o $(IRX:%=irx/%_irx.o)
EE_LIBS = -lpad -lfileXio -lpatches -ldebug

all: $(EE_BIN)

iop/kelfdump.irx:
	$(MAKE) -C iop

irx/kelfdump_irx.c: iop/kelfdump.irx
	@mkdir -p irx
	bin2c $< $@ kelfdump_irx

irx/%_irx.c: $(PS2SDK)/iop/irx/%.irx
	@mkdir -p irx
	bin2c $< $@ $*_irx

clean:
	$(MAKE) -C iop clean
	rm -rf $(EE_BIN) ee/*.o irx

.PHONY: iop/kelfdump.irx

include $(PS2SDK)/samples/Makefile.pref
include $(PS2SDK)/samples/Makefile.eeglobal

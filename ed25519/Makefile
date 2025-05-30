PREFIX	?= arm-none-eabi
CC		= $(PREFIX)-gcc
LD		= $(PREFIX)-gcc
OBJCOPY	= $(PREFIX)-objcopy
OBJDUMP	= $(PREFIX)-objdump
GDB		= $(PREFIX)-gdb
OPENCM3_DIR = ../libopencm3

LDSCRIPT   = stm32f405x6_CCM.ld
LIBNAME    = opencm3_stm32f4
ARCH_FLAGS = -mthumb -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16
DEFINES    = -DSTM32F4 -DCORTEX_M4 #-DWITH_PERFORMANCE_BENCHMARKING
OBJS	   = stm32f4_wrapper.o \
			 crypto/asm/cortex_m4_cswap.o crypto/asm/cortex_m4_reduce25519.o crypto/asm/cortex_m4_sqr_fe25519.o crypto/asm/cortex_m4_mpy_fe25519.o crypto/asm/cortex_m4_add_fe25519.o crypto/asm/cortex_m4_mpy_256.o crypto/asm/cortex_m4_mpy121666.o crypto/asm/cortex_m4_sqr_256.o \
			 crypto/support/randombytes.o \
			 crypto/scalarmult/scalarmult_25519.o \
			 crypto/numerics/fe25519.o crypto/numerics/fe25519_invert.o crypto/numerics/bigint.o crypto/numerics/sc25519.o \
			 crypto/ed25519/ed25519.o \
			 crypto/hash/fips202-masked.o crypto/asm/keccakf1600.o

# -fomit-frame-pointer because error
# 'asm' operand has impossible constraints or there are not enough registers
CFLAGS		+= -O1 -fomit-frame-pointer \
		   -Wall -Wextra -Wimplicit-function-declaration \
		   -Wredundant-decls -Wmissing-prototypes -Wstrict-prototypes \
		   -Wundef -Wshadow \
		   -I$(OPENCM3_DIR)/include \
		   -fno-common $(ARCH_FLAGS) -MD $(DEFINES)
LDFLAGS		+= --static -Wl,--start-group -lc -lgcc -lnosys -Wl,--end-group \
		   -T$(LDSCRIPT) -nostartfiles -Wl,--gc-sections,--print-gc-sections \
		   $(ARCH_FLAGS) \
		   -L$(OPENCM3_DIR)/lib

-include local.mk

all: lib main.bin main.elf

flash: lib main.bin
	st-flash write main.bin 0x8000000


lib:
	@if [ ! "`ls -A $(OPENCM3_DIR)`" ] ; then \
		printf "######## ERROR ########\n"; \
		printf "\tlibopencm3 is not initialized.\n"; \
		printf "\tPlease run (in the root directory):\n"; \
		printf "\t$$ git submodule init\n"; \
		printf "\t$$ git submodule update\n"; \
		printf "\tbefore running make.\n"; \
		printf "######## ERROR ########\n"; \
		exit 1; \
		fi
	make -C $(OPENCM3_DIR)

%.bin: %.elf
	$(OBJCOPY) -Obinary $(*).elf $(*).bin

%.elf: %.o $(OBJS) $(LDSCRIPT)
	$(LD) -o $(*).elf $(*).o $(OBJS) $(LDFLAGS) -l$(LIBNAME)

crypto/asm/%.o: crypto/asm/%.S
	$(CC) $(CFLAGS) -o $@ -c $<

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	find . -name \*.o -type f -exec rm -f {} \;
	find . -name \*.d -type f -exec rm -f {} \;
	rm -f *.elf
	rm -f *.bin


CLANG ?= clang
LLC ?= llc-7

# Путь к заголовкам ядра
KDIR ?= /usr/src/linux-headers-$(shell uname -r)
# Архитектура системы
ARCH ?= $(subst x86_64,x86,$(shell uname -m))

# подключаем директорию с вспомогательными заголовками и некоторые директории с заголовками ядра
CFLAGS = \
	-Ihelpers \
	\
	-I/usr/src/linux-headers-4.19.0-6-common/include \
    -I/usr/src/linux-headers-4.19.0-6-common/arch/$(ARCH)/include \
	-I$(KDIR)/include \
	-I$(KDIR)/include/uapi \
	-I$(KDIR)/include/generated/uapi \
	-I$(KDIR)/arch/$(ARCH)/include \
	-I$(KDIR)/arch/$(ARCH)/include/generated \
	-I$(KDIR)/arch/$(ARCH)/include/uapi \
	-I$(KDIR)/arch/$(ARCH)/include/generated/uapi \
	-D__KERNEL__ \
	\
	-Wno-int-to-void-pointer-cast \
	\
	-fno-stack-protector -O2 -g

# 1. Компилируем С в байт-код LLVM
# 2. Преобразовываем байт-код в объектный код eBPF
xdp_%.o: xdp_%.c Makefile
	$(CLANG) -c -emit-llvm $(CFLAGS) $< -o - | \
	$(LLC) -march=bpf -filetype=obj -o $@

.PHONY: all clean

all: xdp_filter.o xdp_dummy.o

clean:
	rm -f ./*.o

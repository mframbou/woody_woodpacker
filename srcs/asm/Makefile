all: woody_bin

woody.bin: woody.s
	as -o woody.o woody.s
	objcopy -O binary --only-section=.text woody.o woody.bin

woody_bin: woody.bin
	xxd -i woody.bin > payload.h

clean:
	rm -f woody.o

fclean: clean
	rm -f woody.bin payload.h
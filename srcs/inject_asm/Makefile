hello_world.bin: hello_world.s
	as -o hello_world.o hello_world.s
	objcopy -O binary --only-section=.text hello_world.o hello_world.bin
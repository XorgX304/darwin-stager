CFLAGS=-fno-stack-protector -fomit-frame-pointer -fno-exceptions -fPIC
SDK=`xcrun --sdk iphoneos --show-sdk-path`
GCC_BIN=`xcrun --sdk iphoneos -f gcc`
GCC_BASE=$(GCC_BIN) -Os $(CFLAGS) -Wimplicit -isysroot $(SDK)
GCC=$(GCC_BASE) -arch arm64

SDK_OSX=`xcrun --sdk macosx --show-sdk-path`
GCC_BIN_OSX=`xcrun --sdk macosx -f gcc`
GCC_BASE_OSX=$(GCC_BIN_OSX) -Os $(CFLAGS) 
GCC_OSX=$(GCC_BASE_OSX) -arch x86_64

all: clean main_ios main_osx

main_ios: main.c
	$(GCC) -o $@ $^
	ldid -S $@

main_osx: main.c
	$(GCC_OSX) -o $@ $^

shellcode: main_osx
	#python extractshell.py -o main_osx -s shellcode
	./macho.rb
	otool -tv main_osx
	cp vm ../metasploit-framework/data/meterpreter/x64_osx_stage

as: main_asm.s
	as main_asm.s -o main_asm.o
	ld main_asm.o -e _main -o main_asm
	otool -tv main_asm
	otool -t main_asm

clean:
	rm -f *.o main_ios main_osx


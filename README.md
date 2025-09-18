# Sleep-Obfuscation
<img width="584" height="874" alt="image" src="https://github.com/user-attachments/assets/962ff957-3016-4079-83c6-887c53e73dc3" />

Basic Sleep obfuscation technique built as a module on the stardust template by 5pider

features:
1. Indirect syscalls with JOP gadgets
2. Entire obfuscation is done in ROP
3. Malleable rop chain (you can insert frames if you want in case you want stack masking or heap encryption)
    @  when implementing heap encryption do remember that when the heap is encrypted other threads may try to
       access it which may cause the entire process to crash so its recommended for partial heap encryption where
       you encrypt only the data relevant to yourself or you can suspend every other thread before performing the
       full heap encryption
4. Using context switching to queue ROP chains (again you can use other techniques too since its one big rop chain)
5. Shellcode implant so the entire program is about ~8kb combined
6. Flower ROP chain by bakki instead of the plain old regular sleep obfuscation ROP
7. Very silly callstack implementation because I cant use unwind metadata (because shellcode does not store entries nor does clang++ want to give me frame pointers)

(!) I might implement a PE file implementation of this or I might not, its just 
    same thing except I can use more assembly wrappers, stack, and functions to 
    help patch the callstack but I have to patch .relocs since PE files rely on
    them to execute under ASLR conditions

PS. All the code is in [SleepObf.cc](https://github.com/vxtandevarmani/Sleep-Obfuscation/blob/main/Mist/src/SleepKit.cc) and I kept it in one file so it would be simple to copy it into other instances of the template

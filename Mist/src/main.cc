#include <common.h>
#include <constexpr.h>
#include <resolve.h>

using namespace stardust;

extern "C" auto declfn entry(
    _In_ void* args
) -> void {
    stardust::instance()
        .start( args );
}

declfn instance::instance(
    void
) {
    //
    // calculate the shellcode base address + size
    base.address = RipStart();
    base.length  = ( RipData() - base.address ) + END_OFFSET;

    //
    // load the modules from PEB or any other desired way
    //

    if ( ! (( ntdll.handle = resolve::module( expr::hash_string<wchar_t>( L"ntdll.dll" ) ) )) ) {
        return;
    }

    if ( ! (( kernel32.handle = resolve::module( expr::hash_string<wchar_t>( L"kernel32.dll" ) ) )) ) {
        return;
    }
	
	/* SNIP START */
	if ( ! (( msvcrt.handle = resolve::module( expr::hash_string<wchar_t>( L"msvcrt.dll" ) ) )) ) {
        return;
    }
	/* SNIP END */
	
    //
    // let the macro handle the resolving part automatically
    //
    RESOLVE_IMPORT( ntdll );
    RESOLVE_IMPORT( kernel32 );
	RESOLVE_IMPORT( msvcrt );
	
	/* SNIP START */
	if ( ! (( kernel32.LoadLibraryA( "advapi32.dll" ) )) ) {
		return;
	}
	
	if ( ! (( advapi32.handle = resolve::module( expr::hash_string<wchar_t>( L"advapi32.dll" ) ) )) ) {
        return;
    }
	
	//RESOLVE_IMPORT( advapi32 );
	advapi32.SystemFunction036 = (decltype(SystemFunction036)*)(kernel32.GetProcAddress((HMODULE)(advapi32.handle), "SystemFunction036"));
	advapi32.SystemFunction032 = (decltype(SystemFunction032)*)(kernel32.GetProcAddress((HMODULE)(advapi32.handle), "SystemFunction033"));
	// 33 cause funny heh...
 	/* SNIP END */
	
}

void instance::subroutine(void){
	#ifdef DEBUG
		msvcrt.printf("[*] DOING STUFF...\n");
	#endif
	return;
}

auto declfn instance::start(
    _In_ void* arg
) -> void {
	PVOID Retaddr   = __builtin_return_address( 0 );
    DBG_PRINTF( "running from %ls (Pid: %d)\n",
        NtCurrentPeb()->ProcessParameters->ImagePathName.Buffer,
        NtCurrentTeb()->ClientId.UniqueProcess );

    DBG_PRINTF( "shellcode @ %p [%d bytes]\n", base.address, base.length );
	int counter = 0;
	loop:
		INSTRUMENT_CALL();
		Blossom(1000);
		subroutine();
		if(counter != 4){
			counter++;
			#ifdef DEBUG
				msvcrt.printf("[*] Jumping...\n");
			#endif
			asm goto (
				"jmp %l[loop]\n\t"
				:
				:
				:
				: loop
			);
		}
	
	#ifdef DEBUG
				msvcrt.printf("[+] YIPPIEEE...\n");
	#endif
	kernel32.TerminateProcess((HANDLE)-1, 0);
}


/*

auto declfn instance::start(
    _In_ void* arg
) -> void {
    const auto user32 = kernel32.LoadLibraryA( symbol<const char*>( "user32.dll" ) );

    if ( user32 ) {
        DBG_PRINTF( "oh wow look we loaded user32.dll -> %p\n", user32 );
    } else {
        DBG_PRINTF( "okay something went wrong. failed to load user32 :/\n" );
    }

    DBG_PRINTF( "running from %ls (Pid: %d)\n",
        NtCurrentPeb()->ProcessParameters->ImagePathName.Buffer,
        NtCurrentTeb()->ClientId.UniqueProcess );

    DBG_PRINTF( "shellcode @ %p [%d bytes]\n", base.address, base.length );
	
    decltype( MessageBoxA ) * msgbox = RESOLVE_API( reinterpret_cast<uintptr_t>( user32 ), MessageBoxA );

    msgbox( nullptr, symbol<const char*>( "Hello world" ), symbol<const char*>( "caption" ), MB_OK );
}

*/
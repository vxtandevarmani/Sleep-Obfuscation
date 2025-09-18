#ifndef STARDUST_COMMON_H
#define STARDUST_COMMON_H

//
// system related headers
#include <windows.h>
#include <type_traits>
#include <concepts>


//
// stardust related headers
#include <constexpr.h>
#include <macros.h>
#include <memory.h>
#include <native.h>
#include <resolve.h>

extern "C" auto RipData() -> uintptr_t;
extern "C" auto RipStart() -> uintptr_t;

#if defined( DEBUG )
#include <stdio.h>		// SNIPPED
#define DBG_PRINTF( format, ... ) { ntdll.DbgPrint( symbol<PCH>( "[DEBUG::%s::%d] " format ), symbol<PCH>( __FUNCTION__ ), __LINE__, ##__VA_ARGS__ ); }
#else
#define DBG_PRINTF( format, ... ) { ; }
#endif

#ifdef _M_X64
#define END_OFFSET 0x10
#else
#define END_OFFSET 0x10
#endif

/* SNIP START */
typedef struct _USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
} USTRING, *PUSTRING;


/*	When resolving undefined APIs define their signature here	*/
extern "C" {
    NTSTATUS WINAPI SystemFunction032(USTRING *data, USTRING *key);
    BOOLEAN  WINAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);
}

#define THERE_IS_NO_ERROR			(BYTE)(0)
#define ERROR_UNRESOLVED_SYSCALL	(BYTE)(1 << 0)
#define ERROR_UNRESOLVED_GADGETS	(BYTE)(1 << 1)
#define ERROR_UNRESOLVED_MEMORYS	(BYTE)(1 << 2)
#define ERROR_SOMETHING_VERY_WRONG	(BYTE)(1 << 3)

#define JUMP(x)                 \
    do {                       \
        asm goto (             \
            "jmp %l[" #x "]\n"  \
            :                   \
            :                   \
            :                   \
            : x                \
        );                      \
    } while (0)



#define INSTRUMENT_CALL() \
    do { \
        base.frame_idx++; \
        if (!base.callstack) { \
            asm("int3"); \
        } \
		DWORD64* slot_ptr = base.callstack + (base.frame_idx - 1);	\
        __asm__ __volatile__( \
            "mov rax, rsp;" \
            "sub rax, 8;" \
            "mov %0, rax;" \
            : "=m" (*slot_ptr) \
            : \
            : "rax", "rcx" \
        ); \
    } while (0)\

/* you are required to use this snippet 
 * every time you call a function and when you 
 * are done execution in the callee you
 * essentially decrement the callstack index
 * to maintain the behavior of a typical callstack 
 * (if you know better ways of enumerating callstacks 
 * apart from winapi please and frame pointer enumeration 
 * just let me know)
 *\

/* SNIP END */



namespace stardust
{
    template <typename T>
    inline T symbol(T s) {
        return reinterpret_cast<T>(RipData()) - (reinterpret_cast<uintptr_t>(&RipData) - reinterpret_cast<uintptr_t>(s));
    }

    class instance {
        struct {
            uintptr_t address;
            uintptr_t length;
			DWORD64 callstack[32];								/* SNIPPED */
			size_t frame_idx;									/* SNIPPED */
        } base = {};

        struct {
            uintptr_t handle;

            struct {
                D_API( LoadLibraryA )
                D_API( GetProcAddress )
				D_API( RtlCaptureContext )						/* SNIPPED */
				D_API( RtlRestoreContext )						/* SNIPPED */
				D_API( TerminateProcess )						/* SNIPPED */
            };
        } kernel32 = {
            RESOLVE_TYPE( LoadLibraryA ),
            RESOLVE_TYPE( GetProcAddress ),
			RESOLVE_TYPE( RtlCaptureContext ),					/* SNIPPED */
			RESOLVE_TYPE( RtlRestoreContext ),					/* SNIPPED */
			RESOLVE_TYPE( TerminateProcess )					/* SNIPPED */
        };

        struct {
            uintptr_t handle;

            struct
            {
				#ifdef DEBUG
                D_API( DbgPrint )
				#endif
				D_API( memmove )								/* SNIPPED */
				D_API( memset )									/* SNIPPED */
				
            };
        } ntdll = {
			#ifdef DEBUG
            RESOLVE_TYPE( DbgPrint ),
			#endif
			RESOLVE_TYPE( memmove ),							/* SNIPPED */
			RESOLVE_TYPE( memset )								/* SNIPPED */
        };
/* SNIP START */

		struct {
			uintptr_t handle;
			
			struct
			{
				#ifdef DEBUG
				D_API( printf )
				#endif
				D_API( realloc )
				D_API( free )
			};
		} msvcrt = {
			#ifdef DEBUG
			RESOLVE_TYPE( printf ),
			#endif
			RESOLVE_TYPE( realloc ),
			RESOLVE_TYPE( free ),
		};
		
		struct {
			uintptr_t handle;
			
			struct
			{
				D_API( SystemFunction036 )
				D_API( SystemFunction032 )
			};
		} advapi32 = {
			RESOLVE_TYPE( SystemFunction036 ),
			RESOLVE_TYPE( SystemFunction032 )
		};
/* SNIP END */

    public:
        explicit instance();

        auto start(
            _In_ void* arg
        ) -> void;
		
		/* SNIP START */
		BYTE Blossom(DWORD MilliSeconds);
		void subroutine(void);
		/* SNIP END */
    };

    template<typename T = char>
    inline auto declfn hash_string(
        _In_ const T* string
    ) -> uint32_t {
        uint32_t hash = 0x811c9dc5;
        uint8_t  byte = 0;

        while ( * string ) {
            byte = static_cast<uint8_t>( * string++ );

            if ( byte >= 'a' ) {
                byte -= 0x20;
            }

            hash ^= byte;
            hash *= 0x01000193;
        }

        return hash;
    }
}


#endif //STARDUST_COMMON_H

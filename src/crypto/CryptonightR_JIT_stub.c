/* MSVC-only stub for v4_generate_JIT_code.
 *
 * The real implementation in CryptonightR_JIT.c contains x86 JIT code
 * guarded by __x86_64__ (GCC/Clang macro).  On MSVC the
 * function already returns -1 (JIT unavailable), but the heavyweight
 * headers it includes (variant4_random_math.h, CryptonightR_template.h)
 * trigger an MSVC Internal Compiler Error in the PDB type server.
 *
 * This stub provides the same -1 return without the problematic includes.
 */

#include <stdint.h>
#include <stddef.h>
#include "CryptonightR_JIT.h"

int v4_generate_JIT_code(const struct V4_Instruction* code,
                         v4_random_math_JIT_func buf,
                         const size_t buf_size)
{
    (void)code; (void)buf; (void)buf_size;
    return -1;
}

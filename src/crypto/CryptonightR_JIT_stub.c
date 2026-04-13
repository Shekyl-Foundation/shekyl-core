/* WARNING: This stub disables CryptonightR JIT compilation on MSVC.
 *
 * Safety chain: use_v4_jit() in slow-hash.c checks __x86_64__ (GCC/Clang
 * only), so on MSVC the jit flag is always 0 and v4_generate_JIT_code() is
 * never called.  The interpreter path (v4_random_math) is used instead.
 * This stub exists solely to satisfy the linker.
 *
 * If use_v4_jit() is ever changed to also check _M_X64, this stub's -1
 * return will trigger local_abort().  Either implement real JIT for MSVC
 * at that point, or ensure the guard remains GCC/Clang-only.
 *
 * MSVC daemon builds are NOT supported -- the interpreter path is
 * significantly slower than JIT for PoW verification.  Build the daemon
 * with GCC or Clang.
 *
 * Background: The real implementation in CryptonightR_JIT.c contains x86
 * JIT code guarded by __i386 / __x86_64__.  The heavyweight headers it
 * includes (variant4_random_math.h, CryptonightR_template.h) trigger an
 * MSVC Internal Compiler Error in the PDB type server.  This stub
 * provides the same -1 return without the problematic includes.
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

#include <asm.h>

#in
#   r3  channel

#out
#   r3 res

.set    EXI_LOCKS,  0xD3026808

EXIUnlock:
    sync
    lis     %r7,    0xD302
    li      %r4,    0
    #add     %r7,    %r7,    %r3
    #stb     %r4,    EXI_LOCKS@l(%r7)
    stw     %r4,    EXI_LOCKS@l(%r7)
    li      %r3,    1
    blr

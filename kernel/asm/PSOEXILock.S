#include <asm.h>

#in
#   r3  channel

#out
#   r3 res

.set    EXI_LOCKS,  0xD3026808

EXILock:
    li      %r4,    1
    lis     %r7,    0xD302
    ori     %r7,    %r7,    EXI_LOCKS@l

    lwarx   %r3,    0,      %r7
    cmpwi   %r3,    0
    bne     err_out

    stwcx.  %r3,    0,      %r7
    bne-    err_out

    isync
    li      %r3,    1
    blr

badEXILock:
    slwi    %r3,    %r3,    3
    li      %r4,    1
    slw     %r4,    %r4,    %r3
    lis     %r7,    0xD302
    ori     %r7,    %r7,    EXI_LOCKS@l

    lwarx   %r3,    0,      %r7
    and.    %r5,    %r4,    %r3
    bne     locked

    or      %r3,    %r3,    %r4
    stwcx.  %r3,    0,      %r7
    bne-    err_out

    isync
    li      %r3,    1
    blr

locked:
    stwcx.  %r3,    0,      %r7
err_out:
    li      %r3,    0
    blr

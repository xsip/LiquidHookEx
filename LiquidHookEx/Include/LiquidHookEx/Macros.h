#pragma once
#define LH_START(seg) \
    __pragma(code_seg(seg))     \
    __pragma(optimize("", off)) \
    __pragma(runtime_checks("", off)) \
    __pragma(check_stack(off))


#define LH_END()      \
    __pragma(check_stack())     \
    __pragma(runtime_checks("", restore)) \
    __pragma(optimize("", on))  \
    __pragma(code_seg())
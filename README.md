# Token-Manipulator

A practical tool motivated by AIS3 2025 Windows Kernel course.

# 1. Token Stealer

## Windows 25H2 EPROCESS

- [_EPROCESS structure](https://www.vergiliusproject.com/kernels/x64/windows-11/25h2/_EPROCESS)

```cpp
struct _EX_FAST_REF Token;                              // 0x248
```

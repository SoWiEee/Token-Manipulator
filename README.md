# Token-Manipulator

A practical tool motivated by AIS3 2025 Windows Kernel course.

# 1. Token Stealer

## Windows 25H2 EPROCESS

- [_EPROCESS structure](https://www.vergiliusproject.com/kernels/x64/windows-11/25h2/_EPROCESS)

```cpp
struct _EX_FAST_REF Token;                              // 0x248
```

## Usage

1. Use VS 2022 build this solution
2. Open Test mode
```
bcdedit /set testsigning on
```
3. Create a service and start it
```
sc create MyJob type= kernel binPath= "C:\path\to\*.sys"
sc start MyJob
```

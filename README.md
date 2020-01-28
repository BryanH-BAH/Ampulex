# Ampulex
Jedi mind-control a process through Stack Bombing and reflective DLL Loading through shared memory.  Win10/x64 ONLY (https://en.wikipedia.org/wiki/Ampulex)


# Overview

Ampulex is a mashup of two projects - Safebreach Lab's PInjectra (https://github.com/SafeBreach-Labs/pinjectra) and Shellcode Reflective DLL Injection (https://github.com/monoxgas/sRDI).  This project marries these two efforts and provides a way to reflectively inject a DLL in a remote process through a technique called Stack Bombing (Again, pioneered by Safebreach Labs).

# Theory of Operation

ShmemLoader.exe
---------------
> Usage:
> ShmemLoader.exe [path to dll to inject]

This utility maps shared memory, wraps a DLL in shellcode using sRDI, and then places it inside of the shared memory.  The shellcode is designed to process and resolve the DLL it wraps, acting as the Microsoft Windows Linker/Loader.  It will properly resolve all imports of the DLL it wraps.


PInjectra.exe
-------------
> Usage:
> PInjectra.exe 9 [Process name] [anything]

This modified version of PInjectra scans the system for the (case sensitive) process name, enumerates the threads and thread state of the process name, and selects a thread which should be vulnerable to the Stack Bombing technique.  This thread is then accessed using `OpenThread()` and it's stack is swapped out for a ROP chain which maps the shared memory segment, calls `VirtualProtect` to mark the buffer as Read/Execute, and then jumps into the buffer, which contains the shellcode loaded by `ShmemLoader.exe`.

TestProcess.exe
---------------
> Usage
> TestProcess.exe

This provides a vulnerable target with which to test the technique.

BasicDLL.dll
------------
BasicDLL Provides you a DLL with known behavior to inject.  Upon a successful injection, the DLL will print a message to stdout using `printf()` inside the target process.


# Usage

TestProcess.exe

Shmemloader.exe BasicDLL.dll

PInjectra.exe 9 TestProcess.exe blah



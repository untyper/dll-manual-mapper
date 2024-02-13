#pragma once

#include <Windows.h>
#include <fstream>
#include <TlHelp32.h>

using f_load_library_a = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_get_proc_address = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

struct MANUAL_MAPPING_DATA
{
  f_load_library_a p_load_library_a;
  f_get_proc_address p_get_proc_address;
  BYTE* p_base;
  HINSTANCE h_mod;
};

// This overload expects an existing heap allocated buffer for manual mapping
PBYTE mmap_dll(HANDLE process_handle, PBYTE buffer);

// This overload copies the given buffer to a new heap allocated buffer for manual mapping
PBYTE mmap_dll(HANDLE process_handle, const char* source_buffer, int size);

// This overload reads the dll from a file to a heap allocated buffer for manual mapping
PBYTE mmap_dll(HANDLE process_handle, const char* binary_path);

// Unmaps mapped dll from memory at given address
bool munmap_dll(HANDLE process_handle, PBYTE p_target_base);
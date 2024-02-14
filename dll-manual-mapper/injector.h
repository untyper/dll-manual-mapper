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

// Maps dll from buffer to process specified by process handle
PBYTE map_dll(HANDLE process_handle, PBYTE buffer, bool from_file = false  /* reserved for internal use */);

// Maps dll from file to process specified by process handle
PBYTE map_dll(HANDLE process_handle, const char* binary_path);

// Unmaps previously mapped dll from memory at given address
bool unmap_dll(HANDLE process_handle, PBYTE p_target_base);

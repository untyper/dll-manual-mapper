#pragma once

#include <Windows.h>
#include <fstream>
#include <TlHelp32.h>

#include "colors.h"

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

struct MANUAL_MAPPING_DATA
{
  f_LoadLibraryA pLoadLibraryA;
  f_GetProcAddress pGetProcAddress;
  BYTE* pBase;
  HINSTANCE hMod;
};

// This overload expects an existing heap allocated buffer for manual mapping
PBYTE ManualMap(HANDLE process_handle, PBYTE buffer);

// This overload copies the given buffer to a new heap allocated buffer for manual mapping
PBYTE ManualMap(HANDLE process_handle, const char* source_buffer, int size);

// This overload reads the dll from a file to a heap allocated buffer for manual mapping
PBYTE ManualMap(HANDLE process_handle, const char* binary_path);

// Unmaps mapped dll from memory at given address
bool ManualUnmap(HANDLE process_handle, PBYTE pTargetBase);
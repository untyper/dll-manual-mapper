#include "injector.h"

#ifdef MANUAL_MAP_ENABLE_OUTPUT
#include <iostream>
#define COUT              std::cout
#define ENDL              std::endl
#define OUT_ERROR(ARGS)   COUT << ERROR   << ARGS << ENDL
#define OUT_INFO(ARGS)    COUT << INFO    << ARGS << ENDL
#define OUT_SUCCESS(ARGS) COUT << SUCCESS << ARGS << ENDL
#define OUT_WARNING(ARGS) COUT << WARNING << ARGS << ENDL
#else
#define OUT_ERROR(ARGS)
#define OUT_INFO(ARGS)
#define OUT_SUCCESS(ARGS)
#define OUT_WARNING(ARGS)
#endif

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

void __stdcall ShellcodeAttach(MANUAL_MAPPING_DATA* pData);
void __stdcall ShellcodeDetach(MANUAL_MAPPING_DATA* pData);

bool ExecuteShellcode(HANDLE process_handle, void (*Shellcode)(MANUAL_MAPPING_DATA*), MANUAL_MAPPING_DATA data)
{
  /* Allocate space for our data */
  PBYTE mmap_data_buffer = reinterpret_cast<PBYTE>(VirtualAllocEx(process_handle, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  if (!mmap_data_buffer)
  {
    OUT_ERROR("OOPS! We ran into some problems... #496 (" << GetLastError() << ")");
    return false;
  }

  OUT_SUCCESS("Allocated 0x" << std::hex << sizeof(MANUAL_MAPPING_DATA) << " bytes at " << std::hex << (uintptr_t)mmap_data_buffer << " for mmap data");

  /* Write our data */
  if (!WriteProcessMemory(process_handle, mmap_data_buffer, &data, sizeof(MANUAL_MAPPING_DATA), nullptr))
  {
    OUT_ERROR("OOPS! We ran into some problems... #497 (" << GetLastError() << ")");
    return false;
  }

  OUT_SUCCESS("Mapped mmap data");

  /* Allocate space for our shellcode */
  void* pShellcode = VirtualAllocEx(process_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!pShellcode) 
  {
    OUT_ERROR("OOPS! We ran into some problems... #498 (" << GetLastError() << ")");
    VirtualFreeEx(process_handle, mmap_data_buffer, 0, MEM_RELEASE);
    return false;
  }

  OUT_SUCCESS("Allocated shellcode (0x1000 bytes at 0x" << std::hex << (uintptr_t)pShellcode << ")");

  /* Write our shellcode */
  if (!WriteProcessMemory(process_handle, pShellcode, Shellcode, 0x1000, nullptr))
  {
    OUT_ERROR("OOPS! We ran into some problems... #499 (" << GetLastError() << ")");
    return false;
  }

  OUT_SUCCESS("Mapped shellcode");

  /* Create thread */
  HANDLE hThread = CreateRemoteThread(process_handle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), mmap_data_buffer, 0, nullptr);
  if (!hThread) 
  {
    OUT_ERROR("OOPS! We ran into some problems... #500 (" << GetLastError() << ")");

    VirtualFreeEx(process_handle, mmap_data_buffer, 0, MEM_RELEASE);
    VirtualFreeEx(process_handle, pShellcode, 0, MEM_RELEASE);

    return false;
  }

  OUT_SUCCESS("Created thread at 0x" << std::hex << (uintptr_t)pShellcode << " (handle: 0x" << std::hex << hThread << ")");

  CloseHandle(hThread);

  OUT_SUCCESS("Waiting for entry point to return...");

  /* Wait for shellcode to be ran */
  HINSTANCE hCheck = NULL;
  while (!hCheck) 
  {
    DWORD exitcode = 0;
    GetExitCodeProcess(process_handle, &exitcode);

    if (exitcode != STILL_ACTIVE) 
    {
      OUT_ERROR("OOPS! We ran into some problems... #501 (" << exitcode << ")");
      return false;
    }

    MANUAL_MAPPING_DATA data_checked{ 0 };
    ReadProcessMemory(process_handle, mmap_data_buffer, &data_checked, sizeof(data_checked), nullptr);
    hCheck = data_checked.hMod;

    if (hCheck == (HINSTANCE)0x404040) 
    {
      OUT_ERROR("OOPS! We ran into some problems... #502");
      return false;
    }
    else if (hCheck == (HINSTANCE)0x606060) 
    {
      OUT_ERROR("OOPS! We ran into some problems... #503");
      return false;
    }

    Sleep(10);
  }

  OUT_SUCCESS("Entry point returned!");

  /* Free shit */
  if (!VirtualFreeEx(process_handle, pShellcode, 0, MEM_RELEASE))
  {
    OUT_ERROR("Failed to free shellcode");
  }

  if (!VirtualFreeEx(process_handle, mmap_data_buffer, 0, MEM_RELEASE))
  {
    OUT_ERROR("Failed to free mmap data");
  }

  return true;
}

PBYTE ManualMap(HANDLE process_handle, const char* source_buffer, int size)
{
  /* Allocate buffer */
  PBYTE buffer = reinterpret_cast<PBYTE>(malloc(size));
  if (!buffer)
  {
    OUT_ERROR("OOPS! We ran into some problems... #490");
    return nullptr;
  }

  OUT_SUCCESS("Allocated buffer at 0x" << std::hex << (uintptr_t)buffer);

  /* Copy bytes from original source to new source */
  memcpy(buffer, source_buffer, size);
  return ManualMap(process_handle, buffer);
}

PBYTE ManualMap(HANDLE process_handle, const char* binary_path)
{
  /* Check dll file attributes */
  if (GetFileAttributes(binary_path) == INVALID_FILE_ATTRIBUTES)
  {
    OUT_ERROR("OOPS! We ran into some problems... ");
    OUT_ERROR("Failed to find DLL file on disk. Please make sure the path is correct!");
    return nullptr;
  }

  /* Open file */
  std::ifstream binary_file(binary_path, std::ios::binary | std::ios::ate);
  if (binary_file.fail())
  {
    OUT_ERROR("OOPS! We ran into some problems... #488");
    binary_file.close();
    return nullptr;
  }

  /* Get file size */
  std::streampos file_size = binary_file.tellg();
  if (file_size < 0x1000)
  {
    OUT_ERROR("OOPS! We ran into some problems... #489");
    binary_file.close();
    return nullptr;
  }

  OUT_INFO("File size 0x" << std::hex << file_size);

  /* Allocate buffer */
  PBYTE buffer = reinterpret_cast<PBYTE>(malloc(file_size));
  if (!buffer)
  {
    OUT_ERROR("OOPS! We ran into some problems... #490");
    binary_file.close();
    return nullptr;
  }

  OUT_SUCCESS("Allocated buffer at 0x" << std::hex << (uintptr_t)buffer);

  /* Read file */
  binary_file.seekg(0, std::ios::beg);
  binary_file.read(reinterpret_cast<char*>(buffer), file_size);
  binary_file.close();

  return ManualMap(process_handle, buffer);
}

PBYTE ManualMap(HANDLE process_handle, PBYTE buffer)
{
  OUT_INFO("Mapping DLL to target process (handle: 0x" << std::hex << process_handle << ")");

  /* Check file signature */
  if (reinterpret_cast<IMAGE_DOS_HEADER*>(buffer)->e_magic != 0x5A4D)
  {
    OUT_ERROR("OOPS! We ran into some problems... #491");
    free(buffer);
    return nullptr;
  }

  /* Retrieve headers */
  PIMAGE_NT_HEADERS pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer + reinterpret_cast<IMAGE_DOS_HEADER*>(buffer)->e_lfanew);
  PIMAGE_OPTIONAL_HEADER pOldOptHeader = &pOldNtHeader->OptionalHeader;
  PIMAGE_FILE_HEADER pOldFileHeader = &pOldNtHeader->FileHeader;

  /* Check platform */
  if (pOldFileHeader->Machine != CURRENT_ARCH)
  {
    OUT_ERROR("OOPS! We ran into some problems... #492");
    free(buffer);
    return nullptr;
  }

  /* Allocate buffer in target process */
  PBYTE pTargetBase = reinterpret_cast<PBYTE>(VirtualAllocEx(process_handle, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
  if (!pTargetBase)
  {
    OUT_ERROR("OOPS! We ran into some problems... #493 (" << GetLastError() << ")");
    free(buffer);
    return nullptr;
  }

  OUT_SUCCESS("Allocated 0x" << std::hex << pOldOptHeader->SizeOfImage << " bytes in target process at 0x" << std::hex << (uintptr_t)pTargetBase);

  MANUAL_MAPPING_DATA data = { 0 };
  data.pLoadLibraryA = LoadLibraryA;
  data.pGetProcAddress = GetProcAddress;
  data.pBase = pTargetBase;

  /* Write first 0x1000 bytes (header) */
  if (!WriteProcessMemory(process_handle, pTargetBase, buffer, 0x1000, nullptr))
  {
    OUT_ERROR("OOPS! We ran into some problems... #494 (" << GetLastError() << ")");
    return nullptr;
  }

  OUT_SUCCESS("Mapped header");

  /* Iterate sections */
  PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
  for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) 
  {
    if (!pSectionHeader->SizeOfRawData)
      continue;

    /* Map section */
    if (WriteProcessMemory(process_handle, pTargetBase + pSectionHeader->VirtualAddress, buffer + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
    {
      OUT_SUCCESS("Mapped [" << pSectionHeader->Name << "]");
      continue;
    }
    
    /* Failed to map section */
    OUT_ERROR("OOPS! We ran into some problems... #495 (" << GetLastError() << ")");
    
    free(buffer);
    VirtualFreeEx(process_handle, pTargetBase, 0, MEM_RELEASE);

    return nullptr;
  }

  if (!ExecuteShellcode(process_handle, ShellcodeAttach, data))
  {
    VirtualFreeEx(process_handle, pTargetBase, 0, MEM_RELEASE);
    free(buffer);
    return nullptr;
  }

  /* Zero first 0x1000 bytes (header) */
  BYTE emptyBuffer[0x1000] = { 0 };
  memset(emptyBuffer, 0, 0x1000);

  /* Write empty buffer */
  if (!WriteProcessMemory(process_handle, pTargetBase, emptyBuffer, 0x1000, nullptr))
  {
    OUT_WARNING("If you see this message please reboot your system and try again");
  }

  /* Allocate new empty buffer */
  PBYTE emptyBuffer2 = reinterpret_cast<PBYTE>(malloc(1024 * 1024));
  if (!emptyBuffer2) 
  {
    OUT_ERROR("OOPS! We ran into some problems... #504");
    free(buffer);
    return nullptr;
  }

  /* Zero buffer */
  memset(emptyBuffer2, 0, 1024 * 1024);

  /* Zero sections */
  pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
  for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) 
  {
    if (!pSectionHeader->SizeOfRawData)
      continue;
    
    if (strcmp((char*)pSectionHeader->Name, ".pdata") == 0 || strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 || strcmp((char*)pSectionHeader->Name, ".reloc") == 0) 
    {
      if (!WriteProcessMemory(process_handle, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer2, pSectionHeader->SizeOfRawData, nullptr))
      {
        //...
      }
    }
  }

  /* Free shit */
  if (buffer)
  {
    free(buffer);
  }

  //Sleep(500);
  return pTargetBase;
}

bool ManualUnmap(HANDLE process_handle, PBYTE pTargetBase)
{
  OUT_INFO("Unmapping DLL from target process (handle: 0x" << std::hex << process_handle << ") at 0x"  << (PVOID)pTargetBase);

  MANUAL_MAPPING_DATA data = { 0 };
  data.pBase = pTargetBase;

  if (!ExecuteShellcode(process_handle, ShellcodeDetach, data))
  {
    return false;
  }

  if (!VirtualFreeEx(process_handle, pTargetBase, 0, MEM_RELEASE))
  {
    OUT_ERROR("Failed to free mapped memory");
  }

  //Sleep(500);
  return true;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks( "", off )
#pragma optimize( "", off )

void __stdcall ShellcodeAttach(MANUAL_MAPPING_DATA* pData)
{
  if (!pData) 
  {
    pData->hMod = (HINSTANCE)0x404040;
    return;
  }

  PBYTE pBase = pData->pBase;
  auto* pOpt = &reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + reinterpret_cast<PIMAGE_DOS_HEADER>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

  auto _LoadLibraryA = pData->pLoadLibraryA;
  auto _GetProcAddress = pData->pGetProcAddress;
  auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

  PBYTE LocationDelta = (pBase - pOpt->ImageBase);
  if (LocationDelta)
  {
    if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) 
    {
      pData->hMod = (HINSTANCE)0x606060;
      return;
    }

    PIMAGE_BASE_RELOCATION pRelocData = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    
    while (pRelocData->VirtualAddress)
    {
      UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
      PWORD pRelativeInfo = reinterpret_cast<PWORD>(pRelocData + 1);

      for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
      {
        if (RELOC_FLAG(*pRelativeInfo))
        {
          UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
          *pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
        }
      }

      pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
    }
  }

  if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
  {
    PIMAGE_IMPORT_DESCRIPTOR pImportDescr = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    while (pImportDescr->Name)
    {
      char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
      HINSTANCE hDll = _LoadLibraryA(szMod);

      ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
      ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

      if (!pThunkRef)
        pThunkRef = pFuncRef;

      for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
      {
        if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
        {
          *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
        }
        else
        {
          auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
          *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
        }
      }

      ++pImportDescr;
    }
  }

  if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
  {
    auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
    
    for (; pCallback && *pCallback; ++pCallback)
    {
      (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }
  }

  _DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

  pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}

void __stdcall ShellcodeDetach(MANUAL_MAPPING_DATA* pData)
{
  if (!pData) 
  {
    //pData->hMod = (HINSTANCE)0x404040;
    return;
  }

  PBYTE pBase = pData->pBase;
  auto* pOpt = &reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + reinterpret_cast<PIMAGE_DOS_HEADER>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;
  auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

  if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
  {
    auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);

    for (; pCallback && *pCallback; ++pCallback)
    {
      (*pCallback)(pBase, DLL_PROCESS_DETACH, nullptr);
    }
  }

  _DllMain(pBase, DLL_PROCESS_DETACH, nullptr);

  pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}

#include "injector.h"

#ifdef MAP_DLL_ENABLE_OUTPUT
#include <iostream>
#include "colors.h"
#define OUT_ERROR(ARGS)   std::cout << ERROR   << ARGS << std::endl
#define OUT_INFO(ARGS)    std::cout << INFO    << ARGS << std::endl
#define OUT_SUCCESS(ARGS) std::cout << SUCCESS << ARGS << std::endl
#define OUT_WARNING(ARGS) std::cout << WARNING << ARGS << std::endl
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

void __stdcall shellcode_attach(MANUAL_MAPPING_DATA* p_data);
void __stdcall shellcode_detach(MANUAL_MAPPING_DATA* p_data);

bool execute_shellcode(HANDLE process_handle, void (*shellcode)(MANUAL_MAPPING_DATA*), MANUAL_MAPPING_DATA data)
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
  void* p_shellcode = VirtualAllocEx(process_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!p_shellcode) 
  {
    OUT_ERROR("OOPS! We ran into some problems... #498 (" << GetLastError() << ")");
    VirtualFreeEx(process_handle, mmap_data_buffer, 0, MEM_RELEASE);
    return false;
  }

  OUT_SUCCESS("Allocated shellcode (0x1000 bytes at 0x" << std::hex << (uintptr_t)p_shellcode << ")");

  /* Write our shellcode */
  if (!WriteProcessMemory(process_handle, p_shellcode, shellcode, 0x1000, nullptr))
  {
    OUT_ERROR("OOPS! We ran into some problems... #499 (" << GetLastError() << ")");
    return false;
  }

  OUT_SUCCESS("Mapped shellcode");

  /* Create thread */
  HANDLE h_thread = CreateRemoteThread(process_handle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(p_shellcode), mmap_data_buffer, 0, nullptr);
  if (!h_thread) 
  {
    OUT_ERROR("OOPS! We ran into some problems... #500 (" << GetLastError() << ")");

    VirtualFreeEx(process_handle, mmap_data_buffer, 0, MEM_RELEASE);
    VirtualFreeEx(process_handle, p_shellcode, 0, MEM_RELEASE);

    return false;
  }

  OUT_SUCCESS("Created thread at 0x" << std::hex << (uintptr_t)p_shellcode << " (handle: 0x" << std::hex << h_thread << ")");

  CloseHandle(h_thread);

  OUT_SUCCESS("Waiting for entry point to return...");

  /* Wait for shellcode to be ran */
  HINSTANCE h_check = NULL;
  while (!h_check) 
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
    h_check = data_checked.h_mod;

    if (h_check == (HINSTANCE)0x404040) 
    {
      OUT_ERROR("OOPS! We ran into some problems... #502");
      return false;
    }
    else if (h_check == (HINSTANCE)0x606060) 
    {
      OUT_ERROR("OOPS! We ran into some problems... #503");
      return false;
    }

    Sleep(10);
  }

  OUT_SUCCESS("Entry point returned!");

  /* Free shit */
  if (!VirtualFreeEx(process_handle, p_shellcode, 0, MEM_RELEASE))
  {
    OUT_ERROR("Failed to free shellcode");
  }

  if (!VirtualFreeEx(process_handle, mmap_data_buffer, 0, MEM_RELEASE))
  {
    OUT_ERROR("Failed to free mmap data");
  }

  return true;
}

PBYTE map_dll(HANDLE process_handle, const char* binary_path)
{
  /* Check dll file attributes */
  if (GetFileAttributesA(binary_path) == INVALID_FILE_ATTRIBUTES)
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

  return map_dll(process_handle, buffer, true);
}

PBYTE map_dll(HANDLE process_handle, PBYTE buffer, bool from_file)
{
  OUT_INFO("Mapping DLL to target process (handle: 0x" << std::hex << process_handle << ")");

  /* Check file signature */
  if (reinterpret_cast<IMAGE_DOS_HEADER*>(buffer)->e_magic != 0x5A4D)
  {
    OUT_ERROR("OOPS! We ran into some problems... #491");
    if (from_file) free(buffer);
    return nullptr;
  }

  /* Retrieve headers */
  PIMAGE_NT_HEADERS p_old_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer + reinterpret_cast<IMAGE_DOS_HEADER*>(buffer)->e_lfanew);
  PIMAGE_OPTIONAL_HEADER p_old_opt_header = &p_old_nt_header->OptionalHeader;
  PIMAGE_FILE_HEADER p_old_file_header = &p_old_nt_header->FileHeader;

  /* Check platform */
  if (p_old_file_header->Machine != CURRENT_ARCH)
  {
    OUT_ERROR("OOPS! We ran into some problems... #492");
    if (from_file) free(buffer);
    return nullptr;
  }

  /* Allocate buffer in target process */
  PBYTE p_target_base = reinterpret_cast<PBYTE>(VirtualAllocEx(process_handle, nullptr, p_old_opt_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
  if (!p_target_base)
  {
    OUT_ERROR("OOPS! We ran into some problems... #493 (" << GetLastError() << ")");
    if (from_file) free(buffer);
    return nullptr;
  }

  OUT_SUCCESS("Allocated 0x" << std::hex << p_old_opt_header->SizeOfImage << " bytes in target process at 0x" << std::hex << (uintptr_t)p_target_base);

  MANUAL_MAPPING_DATA data = { 0 };
  data.p_load_library_a = LoadLibraryA;
  data.p_get_proc_address = GetProcAddress;
  data.p_base = p_target_base;

  /* Write first 0x1000 bytes (header) */
  if (!WriteProcessMemory(process_handle, p_target_base, buffer, 0x1000, nullptr))
  {
    OUT_ERROR("OOPS! We ran into some problems... #494 (" << GetLastError() << ")");
    return nullptr;
  }

  OUT_SUCCESS("Mapped header");

  /* Iterate sections */
  PIMAGE_SECTION_HEADER p_section_header = IMAGE_FIRST_SECTION(p_old_nt_header);
  for (UINT i = 0; i != p_old_file_header->NumberOfSections; ++i, ++p_section_header) 
  {
    if (!p_section_header->SizeOfRawData)
      continue;

    /* Map section */
    if (WriteProcessMemory(process_handle, p_target_base + p_section_header->VirtualAddress, buffer + p_section_header->PointerToRawData, p_section_header->SizeOfRawData, nullptr))
    {
      OUT_SUCCESS("Mapped [" << p_section_header->Name << "]");
      continue;
    }
    
    /* Failed to map section */
    OUT_ERROR("OOPS! We ran into some problems... #495 (" << GetLastError() << ")");
    
    if (from_file) free(buffer);
    VirtualFreeEx(process_handle, p_target_base, 0, MEM_RELEASE);

    return nullptr;
  }

  if (!execute_shellcode(process_handle, shellcode_attach, data))
  {
    VirtualFreeEx(process_handle, p_target_base, 0, MEM_RELEASE);
    if (from_file) free(buffer);
    return nullptr;
  }

  /* Zero first 0x1000 bytes (header) */
  BYTE empty_buffer[0x1000] = { 0 };
  memset(empty_buffer, 0, 0x1000);

  /* Write empty buffer */
  if (!WriteProcessMemory(process_handle, p_target_base, empty_buffer, 0x1000, nullptr))
  {
    OUT_WARNING("If you see this message please reboot your system and try again");
  }

  /* Allocate new empty buffer */
  PBYTE empty_buffer_2 = reinterpret_cast<PBYTE>(malloc(1024 * 1024));
  if (!empty_buffer_2) 
  {
    OUT_ERROR("OOPS! We ran into some problems... #504");
    if (from_file) free(buffer);
    return nullptr;
  }

  /* Zero buffer */
  memset(empty_buffer_2, 0, 1024 * 1024);

  /* Zero sections */
  p_section_header = IMAGE_FIRST_SECTION(p_old_nt_header);
  for (UINT i = 0; i != p_old_file_header->NumberOfSections; ++i, ++p_section_header) 
  {
    if (!p_section_header->SizeOfRawData)
      continue;
    
    if (strcmp((char*)p_section_header->Name, ".pdata") == 0 || strcmp((char*)p_section_header->Name, ".rsrc") == 0 || strcmp((char*)p_section_header->Name, ".reloc") == 0) 
    {
      if (!WriteProcessMemory(process_handle, p_target_base + p_section_header->VirtualAddress, empty_buffer_2, p_section_header->SizeOfRawData, nullptr))
      {
        //...
      }
    }
  }

  /* Free shit */
  if (buffer)
  {
    if (from_file) free(buffer);
  }

  //Sleep(500);
  return p_target_base;
}

bool unmap_dll(HANDLE process_handle, PBYTE p_target_base)
{
  OUT_INFO("Unmapping DLL from target process (handle: 0x" << std::hex << process_handle << ") at 0x"  << (PVOID)p_target_base);

  MANUAL_MAPPING_DATA data = { 0 };
  data.p_base = p_target_base;

  if (!execute_shellcode(process_handle, shellcode_detach, data))
  {
    return false;
  }

  if (!VirtualFreeEx(process_handle, p_target_base, 0, MEM_RELEASE))
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

void __stdcall shellcode_attach(MANUAL_MAPPING_DATA* p_data)
{
  if (!p_data) 
  {
    p_data->h_mod = (HINSTANCE)0x404040;
    return;
  }

  PBYTE p_base = p_data->p_base;
  auto* p_opt = &reinterpret_cast<PIMAGE_NT_HEADERS>(p_base + reinterpret_cast<PIMAGE_DOS_HEADER>((uintptr_t)p_base)->e_lfanew)->OptionalHeader;

  auto _load_library_a = p_data->p_load_library_a;
  auto _get_proc_address = p_data->p_get_proc_address;
  auto _dll_main = reinterpret_cast<f_DLL_ENTRY_POINT>(p_base + p_opt->AddressOfEntryPoint);

  PBYTE location_delta = (p_base - p_opt->ImageBase);
  if (location_delta)
  {
    if (!p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) 
    {
      p_data->h_mod = (HINSTANCE)0x606060;
      return;
    }

    PIMAGE_BASE_RELOCATION p_reloc_data = reinterpret_cast<PIMAGE_BASE_RELOCATION>(p_base + p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    
    while (p_reloc_data->VirtualAddress)
    {
      UINT amount_of_entries = (p_reloc_data->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
      PWORD p_relative_info = reinterpret_cast<PWORD>(p_reloc_data + 1);

      for (UINT i = 0; i != amount_of_entries; ++i, ++p_relative_info)
      {
        if (RELOC_FLAG(*p_relative_info))
        {
          UINT_PTR* p_patch = reinterpret_cast<UINT_PTR*>(p_base + p_reloc_data->VirtualAddress + ((*p_relative_info) & 0xFFF));
          *p_patch += reinterpret_cast<UINT_PTR>(location_delta);
        }
      }

      p_reloc_data = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(p_reloc_data) + p_reloc_data->SizeOfBlock);
    }
  }

  if (p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
  {
    PIMAGE_IMPORT_DESCRIPTOR p_import_descr = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(p_base + p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    while (p_import_descr->Name)
    {
      char* sz_mod = reinterpret_cast<char*>(p_base + p_import_descr->Name);
      HINSTANCE h_dll = _load_library_a(sz_mod);

      ULONG_PTR* p_thunk_ref = reinterpret_cast<ULONG_PTR*>(p_base + p_import_descr->OriginalFirstThunk);
      ULONG_PTR* p_func_ref = reinterpret_cast<ULONG_PTR*>(p_base + p_import_descr->FirstThunk);

      if (!p_thunk_ref)
        p_thunk_ref = p_func_ref;

      for (; *p_thunk_ref; ++p_thunk_ref, ++p_func_ref)
      {
        if (IMAGE_SNAP_BY_ORDINAL(*p_thunk_ref))
        {
          *p_func_ref = (ULONG_PTR)_get_proc_address(h_dll, reinterpret_cast<char*>(*p_thunk_ref & 0xFFFF));
        }
        else
        {
          auto* p_import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(p_base + (*p_thunk_ref));
          *p_func_ref = (ULONG_PTR)_get_proc_address(h_dll, p_import->Name);
        }
      }

      ++p_import_descr;
    }
  }

  if (p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
  {
    auto* p_tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(p_base + p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    auto* p_callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(p_tls->AddressOfCallBacks);
    
    for (; p_callback && *p_callback; ++p_callback)
    {
      (*p_callback)(p_base, DLL_PROCESS_ATTACH, nullptr);
    }
  }

  _dll_main(p_base, DLL_PROCESS_ATTACH, nullptr);

  p_data->h_mod = reinterpret_cast<HINSTANCE>(p_base);
}

void __stdcall shellcode_detach(MANUAL_MAPPING_DATA* p_data)
{
  if (!p_data) 
  {
    //p_data->h_mod = (HINSTANCE)0x404040;
    return;
  }

  PBYTE p_base = p_data->p_base;
  auto* p_opt = &reinterpret_cast<PIMAGE_NT_HEADERS>(p_base + reinterpret_cast<PIMAGE_DOS_HEADER>((uintptr_t)p_base)->e_lfanew)->OptionalHeader;
  auto _dll_main = reinterpret_cast<f_DLL_ENTRY_POINT>(p_base + p_opt->AddressOfEntryPoint);

  if (p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
  {
    auto* p_tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(p_base + p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    auto* p_callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(p_tls->AddressOfCallBacks);

    for (; p_callback && *p_callback; ++p_callback)
    {
      (*p_callback)(p_base, DLL_PROCESS_DETACH, nullptr);
    }
  }

  _dll_main(p_base, DLL_PROCESS_DETACH, nullptr);

  p_data->h_mod = reinterpret_cast<HINSTANCE>(p_base);
}

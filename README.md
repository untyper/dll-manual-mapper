# dll-manual-mapper
DLL injector by manual mapping

## Features
- Map and unmap DLL
- Map DLL either from memory or file
- Cleaner style (lol)
- Enable output with `MAP_DLL_ENABLE_OUTPUT`

## API
```c++
// dll_mapper.h

// ...

// Maps dll from buffer to process specified by process handle
PBYTE map_dll(HANDLE process_handle, PBYTE buffer);

// Maps dll from file to process specified by process handle
PBYTE map_dll(HANDLE process_handle, const char* dll_file_path);

// Unmaps previously mapped dll from memory at given address
bool unmap_dll(HANDLE process_handle, PBYTE p_dll_address);

// ...

```

## Credits
- https://github.com/patrickcjk/dll-manual-map (Original repo)

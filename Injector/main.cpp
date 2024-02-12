#include <windows.h>
#include <Lmcons.h>
#include <iostream>

#include "colors.h"
#include "injector.h"
#include "dll.h"

// To disable output, remove MANUAL_MAP_ENABLE_OUTPUT from the preprocessors settings in project properties

int main()
{
  try 
  {
    /* Process id of target process */
    DWORD process_id = 9436; /* = explorer.exe */

    /* Get handle to target process */
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    //HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (!process_handle)
    {
        std::cout << ERROR << "OOPS! We ran into some problems... #486" << std::endl;
        std::cin.get();
        return -1;
    }

    /* Map dll to target process */
    PBYTE mapped_address = ManualMap(process_handle, dll, sizeof(dll));

    if (!mapped_address)
    {
        std::cout << ERROR << "OOPS! We ran into some problems... #487" << std::endl;
        std::cin.get();
        return -1;
    }

    std::cout << SUCCESS << "Done mapping! Unmapping in 10s..." << std::endl;

    Sleep(10000);

    bool unmap_status = ManualUnmap(process_handle, mapped_address);
    CloseHandle(process_handle);

    if (!unmap_status)
    {
      std::cout << ERROR << "OOPS! We ran into some problems... #489" << std::endl;
      std::cin.get();
      return -1;
    }

    std::cout << SUCCESS << "Successfully unmapped! Press any key to exit." << std::endl;
  }
  catch (std::exception const& e)
  {
    std::cout << ERROR << "OOPS! An exception occured :(" << std::endl;
    std::cout << ERROR << e.what() << std::endl;
    std::cin.get();
    return -1;
  }

  //std::cout << INFO << "Goodbye! This window will close in 5 seconds" << std::endl;
  //Sleep(5000);

  std::cin.get();
  return 0;
}
///
/// @file PolicyManager
///

#include <Windows.h>

class PolicyManager
{
public:
     // Конструктор
     //
     PolicyManager() 
     {
          moduleAdvApi = NULL;
          moduleNetApi = NULL;
     };

     //
     ~PolicyManager() {};

private:
     HMODULE moduleAdvApi;
     HMODULE moduleNetApi;
};
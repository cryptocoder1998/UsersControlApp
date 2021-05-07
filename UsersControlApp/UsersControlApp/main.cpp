#include <iostream>
#include "policymanager.h"

int main(int argc, char** argv)
{
     PolicyManager policyManager;
     if ( policyManager.GetPolicyHandle() == NULL )
     {
          BOOST_LOG_TRIVIAL(error) << "Policy handle is empty, terminating...";
          return 1;
     }
     return 0;
}
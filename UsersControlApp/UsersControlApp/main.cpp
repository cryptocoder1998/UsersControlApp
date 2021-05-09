#include <iostream>
#include "policymanager.h"
     

int main(int argc, char** argv)
{
     PolicyManager policyManager;
     // Check whether policy handle was opened
     if ( policyManager.GetPolicyHandle() == NULL )
     {
          BOOST_LOG_TRIVIAL(error) << "Policy handle is empty, terminating...";
          //return 1;
     }

     int uiChoice = 0;
     while (1)
     {
          std::cout << UI << "> ";
          std::cin >> uiChoice;
          std::cin.ignore(32767, '\n');

          switch ( uiChoice )
          {
          case DISPLAY_SYSTEM_USERS:
          {
               policyManager.DisplayUsersInfo();
               break;
          }
          case DISPLAY_LOCAL_GROUPS:
          {
               break;
          }
          case DISPLAY_GLOBAL_GROUPS:
          {
               break;
          }
          case CREATE_USER:
          {
               break;
          }
          case CREATE_GROUP:
          {
               break;
          }
          case DELETE_USER:
          {
               break;
          }
          case DELETE_GROUP:
          {
               break;
          }
          case ADD_USER_PRIVELEGE:
          {
               break;
          }
          case ADD_GROUP_PRIVELEGE:
          {
               break;
          }
          case DELETE_USER_PRIVELEGE:
          {
               break;
          }
          case DELETE_GROUP_PRIVELEGE:
          {
               break;
          }
          default:
               std::cout << " Couldn't find such number" << std::endl;
               break;
          }
     }
     return 0;
}
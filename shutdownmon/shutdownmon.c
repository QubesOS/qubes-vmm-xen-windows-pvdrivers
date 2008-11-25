#pragma warning(disable: 4201)
#include <windows.h>
#include <basetyps.h>
#include <stdlib.h>
#include <wtypes.h>
#include <initguid.h>
#include <stdio.h>
#include <string.h>
#include <winioctl.h>
#include <setupapi.h>
#include <ctype.h>

#define SERVICE_ID "ShutdownMon"
#define SERVICE_NAME "Xen Shutdown Monitor"

#define OLD_SERVICE_ID "XenShutdownMon"

DEFINE_GUID(GUID_XEN_IFACE, 0x5C568AC5, 0x9DDF, 0x4FA5, 0xA9, 0x4A, 0x39, 0xD6, 0x70, 0x77, 0x81, 0x9C);


SERVICE_STATUS service_status; 
SERVICE_STATUS_HANDLE hStatus; 

#define LOGFILE "C:\\xsm.log"

int write_log(char* str)
{
   FILE* log;
   log = fopen(LOGFILE, "a+");
   if (log == NULL)
      return -1;
   fprintf(log, "%s\n", str);
   fclose(log);
   return 0;
}

static void
install_service()
{
  SC_HANDLE manager_handle;
  SC_HANDLE service_handle;
  TCHAR path[MAX_PATH];
  TCHAR command_line[MAX_PATH + 10];

  if( !GetModuleFileName( NULL, path, MAX_PATH ) )
  {
    printf("Cannot install service (%d)\n", GetLastError());
    return;
  }

  sprintf(command_line, "\"%s\" -s", path);
  manager_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
 
  if (!manager_handle)
  {
    printf("OpenSCManager failed (%d)\n", GetLastError());
    return;
  }

  service_handle = CreateService( 
    manager_handle, SERVICE_ID, SERVICE_NAME, SERVICE_ALL_ACCESS,
    SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
    SERVICE_ERROR_NORMAL, command_line, NULL, NULL, NULL, NULL, NULL);
 
  if (!service_handle) 
  {
    printf("CreateService failed (%d)\n", GetLastError()); 
    CloseServiceHandle(manager_handle);
    return;
  }

  printf("Service installed\n"); 

  CloseServiceHandle(service_handle); 
  CloseServiceHandle(manager_handle);
}

static void
remove_old_service()
{
  SC_HANDLE manager_handle;
  SC_HANDLE service_handle;

  manager_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
 
  if (!manager_handle)
  {
    printf("OpenSCManager failed (%d)\n", GetLastError());
    return;
  }

  service_handle = OpenService(manager_handle, OLD_SERVICE_ID, DELETE);
 
  if (!service_handle) 
  {
    printf("OpenService failed (%d)\n", GetLastError()); 
    CloseServiceHandle(manager_handle);
    return;
  }

  if (!DeleteService(service_handle))
  {
    printf("DeleteService failed (%d)\n", GetLastError()); 
    CloseServiceHandle(service_handle); 
    CloseServiceHandle(manager_handle);
    return;
  }

  printf("Old Service removed\n"); 

  CloseServiceHandle(service_handle); 
  CloseServiceHandle(manager_handle);
}

static void
remove_service()
{
  SC_HANDLE manager_handle;
  SC_HANDLE service_handle;

  manager_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
 
  if (!manager_handle)
  {
    printf("OpenSCManager failed (%d)\n", GetLastError());
    return;
  }

  service_handle = OpenService(manager_handle, SERVICE_ID, DELETE);
 
  if (!service_handle) 
  {
    printf("OpenService failed (%d)\n", GetLastError()); 
    CloseServiceHandle(manager_handle);
    return;
  }

  if (!DeleteService(service_handle))
  {
    printf("DeleteService failed (%d)\n", GetLastError()); 
    CloseServiceHandle(service_handle); 
    CloseServiceHandle(manager_handle);
    return;
  }

  printf("Service removed\n"); 

  CloseServiceHandle(service_handle); 
  CloseServiceHandle(manager_handle);
}

static void
do_shutdown(BOOL bRebootAfterShutdown)
{
  HANDLE proc_handle = GetCurrentProcess();
  TOKEN_PRIVILEGES *tp;
  HANDLE token_handle;

  if (!OpenProcessToken(proc_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle))
    return;
  tp = malloc(sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES));
  tp->PrivilegeCount = 1;
  if (!LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tp->Privileges[0].Luid))
  {
    CloseHandle(token_handle);
    return;
  }
  tp->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  if (!AdjustTokenPrivileges(token_handle, FALSE, tp, 0, NULL, NULL))
  {
    CloseHandle(token_handle);
    return;
  }

  if (!InitiateSystemShutdownEx(NULL, NULL, 0, TRUE, bRebootAfterShutdown, SHTDN_REASON_FLAG_PLANNED | SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER))
  {
    // Log a message to the system log here about a failed shutdown
  }

  CloseHandle(token_handle);
}

static char *
get_xen_interface_path()
{
  HDEVINFO handle = SetupDiGetClassDevs(&GUID_XEN_IFACE, 0, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  SP_DEVICE_INTERFACE_DATA sdid;
  SP_DEVICE_INTERFACE_DETAIL_DATA *sdidd;
  DWORD buf_len;
  char *path;

  sdid.cbSize = sizeof(sdid);
  if (!SetupDiEnumDeviceInterfaces(handle, NULL, &GUID_XEN_IFACE, 0, &sdid))
    return NULL;
  SetupDiGetDeviceInterfaceDetail(handle, &sdid, NULL, 0, &buf_len, NULL);
  printf("buf_len = %d\n", buf_len);
  sdidd = malloc(buf_len);
  sdidd->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
  if (!SetupDiGetDeviceInterfaceDetail(handle, &sdid, sdidd, buf_len, NULL, NULL))
    return NULL;
  
  path = malloc(strlen(sdidd->DevicePath) + 1);
  strcpy(path, sdidd->DevicePath);
  free(sdidd);
  
  return path;
}

static void
do_monitoring()
{
  char buf[1024];
  char *bufptr = buf;
  HANDLE handle;
  int state;
  char *path;
  DWORD bytes_read;
  char inchar;

  path = get_xen_interface_path();
  if (path == NULL)
    return;

  handle = CreateFile(path, FILE_GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  state = 0;
  for (;;)
  {
    if (service_status.dwCurrentState != SERVICE_RUNNING)
      return;
    if (!ReadFile(handle, &inchar, 1, &bytes_read, NULL))
    {
      CloseHandle(handle);
      return;
    }
    switch (state)
    {
    case 0:
      if (isalnum(inchar))
      {
        *bufptr = inchar;
        bufptr++;
      }
      else if (inchar == '\r')
      {
        *bufptr = 0;
        state = 1;
      }
      else
      {
        bufptr = buf;
      }
      break;
    case 1:
      if (inchar == '\n')
      {
        printf("%s\n", buf);
        if (strcmp("poweroff", buf) == 0 || strcmp("halt", buf) == 0)
        {
          do_shutdown(FALSE);
        }
        else if (strcmp("reboot", buf) == 0)
        {
          do_shutdown(TRUE);
        } 
        else
        {
          // complain here
        }
      }
      state = 0;
      break;
    }
  }
}

void control_handler(DWORD request) 
{ 
  switch(request) 
  { 
    case SERVICE_CONTROL_STOP: 
      service_status.dwWin32ExitCode = 0; 
      service_status.dwCurrentState = SERVICE_STOPPED; 
      SetServiceStatus (hStatus, &service_status);
      return; 
 
    case SERVICE_CONTROL_SHUTDOWN: 
      service_status.dwWin32ExitCode = 0; 
      service_status.dwCurrentState = SERVICE_STOPPED; 
      SetServiceStatus (hStatus, &service_status);
      return; 

    default:
      break;
  } 
 
  SetServiceStatus (hStatus, &service_status);

  return; 
}

void service_main(int argc, char *argv[]) 
{ 
  UNREFERENCED_PARAMETER (argc);
  UNREFERENCED_PARAMETER (argv);

  write_log("Entering service_main\n"); 

  service_status.dwServiceType = SERVICE_WIN32; 
  service_status.dwCurrentState =  SERVICE_START_PENDING; 
  service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  service_status.dwWin32ExitCode = 0; 
  service_status.dwServiceSpecificExitCode = 0; 
  service_status.dwCheckPoint = 0; 
  service_status.dwWaitHint = 0; 
 
  hStatus = RegisterServiceCtrlHandler(SERVICE_ID, (LPHANDLER_FUNCTION)control_handler); 
  if (hStatus == (SERVICE_STATUS_HANDLE)0) 
  { 
    write_log("RegisterServiceCtrlHandler failed\n"); 
    return; 
  }  

  service_status.dwCurrentState = SERVICE_RUNNING; 
  SetServiceStatus(hStatus, &service_status);

  do_monitoring();

write_log("All done\n"); 

  return; 
}


static void
print_usage(char *name)
{
  printf("Usage:\n");
  printf("  %s <options>\n", name);
  printf("\n");
  printf("Options:\n");
  printf(" -d run in foreground\n");
  printf(" -s run as service\n");
  printf(" -i install service\n");
  printf(" -u uninstall service\n");
  printf(" -o remove the old .NET service\n");
}

int __cdecl
main(
    __in ULONG argc,
    __in_ecount(argc) PCHAR argv[]
)
{
  SERVICE_TABLE_ENTRY service_table[2];

  if (argc == 0)
  {
    print_usage("shutdownmon");
    return 1;
  }
  if (argc != 2 || (argc == 2 && (strlen(argv[1]) != 2 || argv[1][0] != '-')))
  {
    print_usage(argv[0]);
    return 1;
  }

  switch(argv[1][1])
  {
  case 'd':
    service_status.dwCurrentState = SERVICE_RUNNING;
    do_monitoring();
    break;
  case 's':
    service_table[0].lpServiceName = SERVICE_ID;
    service_table[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)service_main;

    service_table[1].lpServiceName = NULL;
    service_table[1].lpServiceProc = NULL;

    StartServiceCtrlDispatcher(service_table);
    break;
  case 'i':
    install_service();
    break;
  case 'u':
    remove_service();
    break;
  case 'o':
    remove_old_service();
    break;
  default:
    print_usage(argv[0]);
    return 1;
  }
  return 0;
}


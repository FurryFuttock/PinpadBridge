#include "pch.h"
#include "MilliwaysServiceManager.h"
#include "Utils.h"
#include <msclr\marshal.h>

using namespace System;
using namespace msclr::interop;

//#pragma comment(lib, "SetupAPI.lib")
#pragma comment(lib, "Advapi32.lib")

namespace MilliwaysServiceManager {
    ServiceManager::ServiceManager()
        : service_manager_handle(NULL)
        , service_handle(NULL)
        , service_name(nullptr)
    {
    }

    ServiceManager::~ServiceManager()
    {
        this->!ServiceManager();
    }

    ServiceManager::!ServiceManager()
    {
        if (service_handle != NULL)
        {
            CloseServiceHandle(service_handle);
            service_handle = NULL;
        }
        if (service_manager_handle != NULL)
        {
            CloseServiceHandle(service_manager_handle);
            service_manager_handle = NULL;
        }
    }

    int ServiceManager::OpenServiceManager()
    {
        if (service_manager_handle != NULL)
            return 0;

        service_manager_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (service_manager_handle == NULL)
            return -1;

        return 0;
    }

    int ServiceManager::OpenService(String ^service_name)
    {
        // open a handle to the service manager
        if (OpenServiceManager())
            return -1;

        // if we already have a handle to the service then check if it is our service 
        if (service_handle != NULL)
        {
            // if this is our service then we are done
            if ((this->service_name != nullptr) && String::Equals(this->service_name, service_name))
                return 0;

            // not our service so clean up
            CloseServiceHandle(service_handle);
            service_handle = NULL;
            service_name = nullptr;
        }

        service_handle = ::OpenService(service_manager_handle, (gcnew marshal_context())->marshal_as<const TCHAR *>(service_name), SERVICE_ALL_ACCESS);
        this->service_name = service_name;

        return -(service_handle == NULL);
    }

    int ServiceManager::Install(String ^service_name, String ^display_name, System::String ^path, SERVICE_TYPE service_type, SERVICE_START_TYPE start_type, SERVICE_ERROR_TYPE error_control, System::Collections::Generic::List<System::String^>^ dependencies)
    {
        if (OpenServiceManager())
            return -1;

        if (service_handle != NULL)
        {
            CloseServiceHandle(service_handle);
            service_handle = NULL;
        }

        System::Text::StringBuilder ^sb = gcnew System::Text::StringBuilder();
        for each (System::String^ s in dependencies)
        {
            sb->Append(s);
            sb->Append("\0");
        }
        sb->Append("\0");
        const TCHAR *szDependencies = (gcnew marshal_context())->marshal_as<const TCHAR *>(sb->ToString());

        SC_HANDLE service_handle = CreateService(
            service_manager_handle,
            (gcnew marshal_context())->marshal_as<const TCHAR *>(service_name),
            (gcnew marshal_context())->marshal_as<const TCHAR *>(display_name),
            SERVICE_ALL_ACCESS,
            (DWORD)service_type,
            (DWORD)start_type,
            (DWORD)error_control,
            (gcnew marshal_context())->marshal_as<const TCHAR *>(path),
            NULL,
            NULL,
            szDependencies, // dependencies
            NULL,
            NULL
        );
        if (!service_handle)
            WRITE_LOG(GetLastError(), "%s", __FUNCTION__);

        return -(service_handle == NULL);
    }

    int ServiceManager::Uninstall(String ^service_name)
    {
        if (OpenService(service_name))
            return -1;

        if (Stop(service_name))
            return -1;

        if (!DeleteService(service_handle))
            return -1;

        // we must close all handles to the service manager so that the service can be deleted
        CloseServiceHandle(service_handle);
        service_handle = NULL;
        CloseServiceHandle(service_manager_handle);
        service_manager_handle = NULL;

        return 0;
    }

    DWORD ServiceManager::QueryServiceStatus()
    {
        SERVICE_STATUS stat;
        if (!::QueryServiceStatus(service_handle, &stat))
            return -1;
        return stat.dwCurrentState;
    }

    DWORD ServiceManager::ControlService(DWORD state)
    {
        SERVICE_STATUS stat;
        if (!::ControlService(service_handle, state, &stat))
        {
            // GetLastError() != ERROR_SERVICE_NOT_ACTIVE (1062)  then throw exception
            if (GetLastError() != 1062)
                return -1;
        }
        return stat.dwCurrentState;
    }

    int ServiceManager::Stop(System::String ^service_name)
    {
        if (OpenService(service_name))
            return -1;

        if (QueryServiceStatus() != SERVICE_STOPPED)
        {
            if (ControlService(SERVICE_STOP) != SERVICE_STOPPED)
            {
                do
                    System::Threading::Thread::Sleep(1000);
                while (QueryServiceStatus() == SERVICE_STOP_PENDING);
            }

            return -(QueryServiceStatus() != SERVICE_STOPPED);
        }
        else
            return 0;
    }

    int ServiceManager::Start(System::String ^service_name)
    {
        if (OpenService(service_name))
            return -1;

        switch (QueryServiceStatus())
        {
        case SERVICE_STOPPED:
            return -!StartService(service_handle, 0, NULL);
        case SERVICE_RUNNING:
            return 0;
        default:
            return -1;
        }
    }
};

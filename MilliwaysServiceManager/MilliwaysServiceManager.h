#pragma once

using namespace System;

namespace MilliwaysServiceManager {
    public ref class ServiceManager
    {
    protected:
        SC_HANDLE service_manager_handle;
        SC_HANDLE service_handle;
        System::String ^service_name;

        int OpenServiceManager();
        int OpenService(System::String ^service_name);
        DWORD QueryServiceStatus();
        DWORD ControlService(DWORD state);

    public:
        ServiceManager(void);
        ~ServiceManager(void);
        !ServiceManager(void);

        enum class SERVICE_TYPE : DWORD
        {
            KERNEL_DRIVER = SERVICE_KERNEL_DRIVER,
            FILE_SYSTEM_DRIVER = SERVICE_FILE_SYSTEM_DRIVER,
            RECOGNIZER_DRIVER = SERVICE_RECOGNIZER_DRIVER,
            DRIVER_ALL = (KERNEL_DRIVER | FILE_SYSTEM_DRIVER | RECOGNIZER_DRIVER),
            ADAPTER = SERVICE_ADAPTER,
            WIN32_OWN_PROCESS = SERVICE_WIN32_OWN_PROCESS,
            WIN32_SHARE_PROCESS = SERVICE_WIN32_SHARE_PROCESS,
            WIN32_ALL = (WIN32_OWN_PROCESS | WIN32_SHARE_PROCESS),
            INTERACTIVE_PROCESS = SERVICE_INTERACTIVE_PROCESS,
            ALL = (WIN32_ALL | ADAPTER | DRIVER_ALL | INTERACTIVE_PROCESS)
        };

        enum class SERVICE_START_TYPE : DWORD
        {
            BOOT = SERVICE_BOOT_START,
            SYSTEM = SERVICE_SYSTEM_START,
            AUTO = SERVICE_AUTO_START,
            MANUAL = SERVICE_DEMAND_START,
            DISABLED = SERVICE_DISABLED
        };

        enum class SERVICE_ERROR_TYPE : DWORD
        {
            NONE = SERVICE_ERROR_IGNORE,
            NORMAL = SERVICE_ERROR_NORMAL,
            SEVERE = SERVICE_ERROR_SEVERE,
            CRITICAL = SERVICE_ERROR_CRITICAL
        };

        /// <summary>
        /// Register executable as a service with the local Windows service manager 
        /// </summary>
        /// <param name="service_name">Name for this service. Must be unique.</param>
        /// <param name="display_name">Name to be displayed in the service manager.</param>
        /// <param name="path">Path to the service executable.</param>
        /// <param name="service_type">What kind of service to create.</param>
        /// <param name="service_type">How to start the service.</param>
        int Install(System::String ^service_name, System::String ^display_name, System::String ^path, SERVICE_TYPE service_type,
            SERVICE_START_TYPE start_type, SERVICE_ERROR_TYPE error_control, System::Collections::Generic::List<System::String^>^ dependencies);

        int Uninstall(System::String ^service_name);
        int Start(System::String ^service_name);
        int Stop(System::String ^service_name);
    };
}

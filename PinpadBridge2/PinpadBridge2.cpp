// PinpadBridge2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "soapH.h"
#include "json.h"

#include <vector>
#include <string>
#include <sstream>

#include <stdio.h>
#include <stdarg.h>

#include <winsvc.h>

#pragma comment(lib, "advapi32.lib")

#define LOGGING_ID "soap_LOGGING-1.0"
#define WRITE_LOG(...) write_log(__FILE__, __LINE__, __VA_ARGS__)
#define GET_PRIVATE_PROFILE_STRING(section, entry, default_value, output_value, sizeof_output_value, path) if (!GetPrivateProfileString(section, entry, "", output_value, sizeof_output_value, path)) { strncpy(output_value, default_value, sizeof_output_value); WRITE_LOG("[%s]%s not found in %s, using default value %s", section, entry, path, default_value); }

/* Don't need a namespace table. We put an empty one here to avoid link errors */
struct Namespace namespaces[] = { {NULL, NULL} };

static volatile bool run = false;
static bool log_to_file = false;
static int port = 8123;
static int recv_timeout = 10;
static int keep_alive = 0;

struct logging_data
{
    int(*fsend)(struct soap*, const char*, size_t); /* to save and use send callback */
    size_t(*frecv)(struct soap*, char*, size_t); /* to save and use recv callback */
};

static const char logging_id[] = LOGGING_ID;

static void write_log(const char *file, int line, FILE* f, const char *format, va_list arg)
{
    // remove the path from the file name
    const char *p = strrchr(file, '\\');
    if (p)
        file = p + 1;

    // get the time stamps
    time_t log_time = time(0);
    char date_stamp[9], time_stamp[9];
    strftime(time_stamp, sizeof(time_stamp), "%H:%M:%S", localtime(&log_time));
    strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", localtime(&log_time));

    fprintf(f, "%s@%s [%s@%05i] ", date_stamp, time_stamp, file, line);
    vfprintf(f, format, arg);
    fprintf(f, "\n");
}

static void write_log(const char *file, int line, const char *format, ...)
{
    // Get the argument list
    va_list arg;
    va_start(arg, format);

    // If we have to log to a file then ...
    if (log_to_file)
    {
        // Get the executable path
        char file_path[MAX_PATH];
        DWORD file_path_length = GetModuleFileName(NULL, file_path, sizeof(file_path));

        // Create the log path from the executable path
        char *ext = strrchr(file_path, '.');
        if (ext)
        {
            strcpy(ext, ".log");
        }

        // Open file file
        FILE *f = fopen(file_path, "a");

        // Copy the argument list
        va_list arg1;
        va_copy(arg1, arg);

        // Write log
        write_log(file, line, f, format, arg1);

        // Terminate the argument list
        va_end(arg1);

        // Close the file
        fclose(f);
    }

    // Log to the console
    write_log(file, line, stderr, format, arg);

    // Terminate the argument list
    va_end(arg);
}

static void write_log_system_error(const char *file, int line, const std::string &prompt, DWORD error)
{
    char *message;
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, error, 0, (LPSTR)&message, 0, NULL);
    if (message)
    {
        // Remove trailing end of line characters
        for (size_t i = strlen(message) - 1; (i > 0) && (message[i] <= ' '); i--)
        {
            message[i] = 0;
        }
        write_log(file, line, "%s: %s", prompt.c_str(), message);
        LocalFree(message);
    }
    else
    {
        write_log(file, line, "%s", prompt.c_str());
    }
}

static void write_log_json(const char *prompt, int indent, value &v)
{
    WRITE_LOG("%s%*.*s{", prompt, indent, indent, "");
    indent++;

    value::const_iterator i;
    for (i = v.begin(); i != v.end(); i++)
    {
        if (i->is_struct())
        {
            write_log(prompt, indent, static_cast<value>(*i));
        }
        else if (i->is_null())
        {
            WRITE_LOG("%s%*.*s%s: %s", prompt, indent, indent, "", i.name(), "null");
        }
        else if (i->is_bool())
        {
            WRITE_LOG("%s%*.*s%s: %s", prompt, indent, indent, "", i.name(), i->is_true() ? "true" : "false");
        }
        else if (i->is_int())
        {
            WRITE_LOG("%s%*.*s%s: %i", prompt, indent, indent, "", i.name(), static_cast<int>(*i));
        }
        else if (i->is_double())
        {
            WRITE_LOG("%s%*.*s%s: %f", prompt, indent, indent, "", i.name(), static_cast<double>(*i));
        }
        else if (i->is_string())
        {
            WRITE_LOG("%s%*.*s%s: %s", prompt, indent, indent, "", i.name(), static_cast<const char *>(*i));
        }
        else if (i->is_dateTime())
        {
            WRITE_LOG("%s%*.*s%s: %s", prompt, indent, indent, "", i.name(), static_cast<const char *>(*i));
        }
        else if (i->is_array())
        {
            WRITE_LOG("%s%*.*s[", prompt, indent, indent, "");
            indent++;

            _array_iterator j;
            for (j = static_cast<_array>(*i).begin(); j != static_cast<_array>(*i).begin(); j++)
            {
                write_log(prompt, indent, static_cast<value>(*j));
            }

            indent--;
            WRITE_LOG("%s%*.*s]", prompt, indent, indent, "");
        }
    }

    indent--;
    WRITE_LOG("%s%*.*s}", prompt, indent, indent, "");
}

static size_t logging_recv(struct soap *soap, char *buf, size_t len)
{
    struct logging_data *data = (struct logging_data*)soap_lookup_plugin(soap, logging_id);
    size_t res;

    /* get data from old recv callback */
    res = data->frecv(soap, buf, len);

    /* log received data */
    if (res > 0)
        WRITE_LOG("RECV [%*.*s]", res, res, buf);

    return res;
}

static int logging_send(struct soap *soap, const char *buf, size_t len)
{
    struct logging_data *data = (struct logging_data*)soap_lookup_plugin(soap, logging_id);

    // if it's not too big then log it
    if (len > 0)
        WRITE_LOG("SEND [%*.*s]", len, len, buf);

    return data->fsend(soap, buf, len); /* pass data on to old send callback */
}

/* used by plugin registry function */
static int logging_init(struct soap *soap, struct logging_data *data)
{
    data->fsend = soap->fsend; /* save old recv callback */
    data->frecv = soap->frecv; /* save old send callback */
    soap->fsend = logging_send; /* replace send callback with ours */
    soap->frecv = logging_recv; /* replace recv callback with ours */
    return SOAP_OK;
}

static void logging_delete(struct soap *soap, struct soap_plugin *p)
{
    struct logging_data *data = (struct logging_data*)p->data;

    /* restore callbacks */
    soap->fsend = data->fsend; /* replace send callback with ours */
    soap->frecv = data->frecv; /* replace recv callback with ours */

    /* free allocated plugin data. If fcopy() is not set, then this function is
       not called for all copies of the plugin created with soap_copy(). In this
       example, the fcopy() callback is omitted and the plugin data is shared by
       the soap copies created with soap_copy() */
    SOAP_FREE(soap, p->data);
}

/* plugin registry function, invoked by soap_register_plugin */
static int logging(struct soap *soap, struct soap_plugin *p, void *arg)
{
    p->id = logging_id;
    /* create local plugin data */
    p->data = (void*)SOAP_MALLOC(soap, sizeof(struct logging_data));
    /* register the destructor */
    p->fdelete = logging_delete;
    /* if OK then initialize */
    if (p->data)
    {
        if (logging_init(soap, (struct logging_data*)p->data))
        {
            SOAP_FREE(soap, p->data); /* error: could not init */
            return SOAP_EOM; /* return error */
        }
    }
    return SOAP_OK;
}

int register_gsoap_log_plugin(struct soap *soap)
{
    int rc = -1;
    WRITE_LOG("register logging...");
    if (soap_register_plugin_arg(soap, logging, NULL))
    {
        const char *c, *v = NULL, *s, **d;

        // log fault (copied from soap_print_fault)
        d = soap_faultcode(soap);
        if (!*d)
            soap_set_fault(soap);
        c = *d;
        if (soap->version == 2)
            v = *soap_faultsubcode(soap);
        s = *soap_faultstring(soap);
        d = soap_faultdetail(soap);
        WRITE_LOG("%s%d fault: %s [%s]\n\"%s\"\nDetail: %s\n", soap->version ? "SOAP 1." : "Error ", soap->version ? (int)soap->version : soap->error, c, v ? v : "no subcode", s ? s : "[no reason]", d && *d ? *d : "[no detail]");
        goto fail;
    }

    rc = 0;

fail:
    return rc;
}

/// serialport namespace implements the serial port control and Pinpad protocol
/// I suppose that I should really separate the protocol out, but not now
namespace serialport
{
#define STX 0x02
#define ETX 0x03
#define ACK 0x06
#define NAK 0x15

    struct parameters
    {
        std::string port;
        long baudrate;
        int databits, parity, flowcontrol;
        double stopbits;
    };

    static HANDLE open(const struct parameters &parameters, DWORD buffer_size)
    {
        // local data
        HANDLE			port_handle = NULL;
        std::string     port_path = std::string("\\\\.\\") + parameters.port;
        COMMTIMEOUTS	CommTimeOuts;
        DCB				dcb;

        // open the serial port
        port_handle = ::CreateFile(
            port_path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        // if the port did not open then fail 
        if (INVALID_HANDLE_VALUE == port_handle)
        {
            write_log_system_error(__FILE__, __LINE__, std::string("Error opening port ") + parameters.port.c_str(), GetLastError());
            goto fail;
        }

        // if the device buffers do not setup then fail
        if ((INVALID_HANDLE_VALUE != port_handle) && !SetupComm(port_handle, buffer_size, buffer_size))
        {
            write_log_system_error(__FILE__, __LINE__, "Error setting buffer size", GetLastError());
            goto fail;
        }

        // purge any information in the buffer
        PurgeComm(port_handle, PURGE_TXABORT | PURGE_RXABORT | PURGE_TXCLEAR | PURGE_RXCLEAR);

        // set the comms timeouts
        CommTimeOuts.ReadIntervalTimeout = MAXDWORD;
        CommTimeOuts.ReadTotalTimeoutMultiplier = 0;
        CommTimeOuts.ReadTotalTimeoutConstant = 0;
        CommTimeOuts.WriteTotalTimeoutMultiplier = 0;
        CommTimeOuts.WriteTotalTimeoutConstant = 0;
        SetCommTimeouts(port_handle, &CommTimeOuts);

        // set the dcb size
        dcb.DCBlength = sizeof(DCB);

        // if the comms state could not be read then fail
        if (!GetCommState(port_handle, &dcb))
        {
            write_log_system_error(__FILE__, __LINE__, "Error getting comm state", GetLastError());
            goto fail;
        }

        // set the baud rate
        switch (parameters.baudrate)
        {
        case 110: dcb.BaudRate = CBR_110; break;
        case 300: dcb.BaudRate = CBR_300; break;
        case 600: dcb.BaudRate = CBR_600; break;
        case 1200: dcb.BaudRate = CBR_1200; break;
        case 2400: dcb.BaudRate = CBR_2400; break;
        case 4800: dcb.BaudRate = CBR_4800; break;
        case 9600: dcb.BaudRate = CBR_9600; break;
        case 14400: dcb.BaudRate = CBR_14400; break;
        case 19200: dcb.BaudRate = CBR_19200; break;
        case 38400: dcb.BaudRate = CBR_38400; break;
        case 57600: dcb.BaudRate = CBR_57600; break;
        case 115200: dcb.BaudRate = CBR_115200; break;
        case 128000: dcb.BaudRate = CBR_128000; break;
        case 256000: dcb.BaudRate = CBR_256000; break;
        }

        // set the data bits
        dcb.ByteSize = (unsigned char)parameters.databits;

        // set the stop bits
        switch (static_cast<int>(parameters.stopbits * 10))
        {
        case 10: dcb.StopBits = ONESTOPBIT; break;
        case 15: dcb.StopBits = ONE5STOPBITS; break;
        case 20: dcb.StopBits = TWOSTOPBITS; break;
        }

        // set the parity
        switch (parameters.parity)
        {
        case 0: dcb.Parity = NOPARITY; break;
        case 1: dcb.Parity = ODDPARITY; break;
        case 2: dcb.Parity = EVENPARITY; break;
        case 3: dcb.Parity = MARKPARITY; break;
        case 4: dcb.Parity = SPACEPARITY; break;
        }
        dcb.fParity = parameters.parity ? TRUE : FALSE;

        // disable DTR/DSR hardware flow control
        dcb.fDtrControl = DTR_CONTROL_DISABLE;
        dcb.fOutxDsrFlow = FALSE;

        // if RTS/CTS flow control enabled then ...
        if (parameters.flowcontrol == 1)
        {
            // begin
            // enable RTS/CTS flow control
            dcb.fOutxCtsFlow = TRUE;
            dcb.fRtsControl = RTS_CONTROL_HANDSHAKE;
        }
        // rts/cts flow control disabled so ...
        else
        {
            // begin
            // invalidate hardware flow control
            dcb.fOutxCtsFlow = FALSE;
            dcb.fRtsControl = RTS_CONTROL_DISABLE;
        }

        // if XON/XOFF flow control enabled then ...
        if (parameters.flowcontrol == 2)
        {
            // begin
            // setup software flow control
            dcb.fInX = dcb.fOutX = TRUE;
            dcb.XonChar = 17;
            dcb.XoffChar = 19;
            dcb.XonLim = 100;
            dcb.XoffLim = 100;
        }
        // rts/cts flow control disabled so ...
        else
        {
            // begin
            // disable software flow control
            dcb.fInX = dcb.fOutX = FALSE;
        }

        // other various settings
        dcb.fBinary = TRUE;

        // if the comms state did not set then fail
        if (!SetCommState(port_handle, &dcb))
        {
            write_log_system_error(__FILE__, __LINE__, "Error setting comm state", GetLastError());
            goto fail;
        }

        // return the success port
        return port_handle;

    fail:
        if (port_handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(port_handle);
        }
        return NULL;
    }

    static void close(HANDLE &port_handle)
    {
        if (port_handle)
        {
            CloseHandle(port_handle);
            port_handle = NULL;
        }
    }

    static DWORD wait(HANDLE port_handle, int timeout_s)
    {
        COMSTAT	com_stat{ 0 };
        for (int i = 0; (i < (timeout_s * 10)) && !com_stat.cbInQue; i++)
        {
            DWORD   error;
            ClearCommError(port_handle, &error, &com_stat);
            if (!com_stat.cbInQue)
            {
                Sleep(100);
            }
        }
        return com_stat.cbInQue;
    }

    static bool send(HANDLE port_handle, const std::vector<std::string> &request, int ack_timeout_s)
    {
        // Create the message
        // <STX>Field0|Field1|...|Fieldn|<ETX><LRC>
        std::vector<uint8_t> data;
        data.push_back(STX);
        for (std::vector<std::string>::const_iterator i = request.cbegin(); i != request.cend(); i++)
        {
            for (std::string::const_iterator j = i->cbegin(); j != i->cend(); j++)
            {
                data.push_back(*j);
            }
            data.push_back('|');
        }
        data.push_back(ETX);

        // Calculate the LRC
        // The LRC is calculated on everything AFTER STX
        // We initialised LRC with STX so when we process STX it will go back to 0
        uint8_t lrc = STX;
        for (std::vector<uint8_t>::const_iterator i = data.cbegin(); i != data.cend(); i++)
        {
            lrc ^= *i;
        }
        data.push_back(lrc);

        // Send the packet
        WRITE_LOG("Send: %*.*s", data.size(), data.size(), data.data());
        DWORD bytes = 0;
        if (!WriteFile(port_handle, data.data(), data.size(), &bytes, NULL) || (bytes != data.size()))
        {
            WRITE_LOG("Error sending data");
            return FALSE;
        }

        // Wait for ACK
        if (!wait(port_handle, ack_timeout_s))
        {
            WRITE_LOG("No ACK");
            return FALSE;
        }

        // Check ack
        uint8_t ack{ 0 };
        if (!ReadFile(port_handle, &ack, 1, &bytes, NULL) || (ack != ACK))
        {
            WRITE_LOG("Invalid ACK %i/%c", ack, ack);
            return FALSE;
        }

        // We were successful
        return true;
    }

    static bool recv(HANDLE port_handle, std::vector<std::string> &response, int command_timeout_s)
    {
        class ReceiveStatus
        {
        public:
            typedef enum { error = -1, idle, data, lrc, done } type;
            static std::string ToString(type t)
            {
                switch (t)
                {
                case error: return "ERROR";
                case idle: return "IDLE";
                case data: return "DATA";
                case lrc: return "LRC ";
                case done: return "DONE";
                }
                return "UNKNOWN";
            }
        };
        ReceiveStatus::type receive_status = ReceiveStatus::idle;
        std::vector<uint8_t> data;
        uint8_t received_lrc;

        while ((receive_status != ReceiveStatus::done) && (receive_status != ReceiveStatus::error) && wait(port_handle, command_timeout_s))
        {
            DWORD bytes_recv;
            char buffer[256];
            if (!ReadFile(port_handle, buffer, sizeof(buffer), &bytes_recv, NULL) || !bytes_recv)
            {
                WRITE_LOG("No response");
                receive_status = ReceiveStatus::error;
                continue;
            }
            WRITE_LOG("Receive %lu bytes", bytes_recv);

            for (DWORD byte = 0; byte < bytes_recv; byte++)
            {
                uint8_t chr = buffer[byte];

                // If we have an STX then restart the state machine
                if ((chr == STX) && (receive_status != ReceiveStatus::lrc))
                {
                    receive_status = ReceiveStatus::idle;
                    data.clear();
                }
                WRITE_LOG("Receive status=%s chr=%i/%c", ReceiveStatus::ToString(receive_status).c_str(), chr, chr);

                // Store this character
                data.push_back(chr);
                received_lrc ^= chr;

                // Process this character
                switch (receive_status)
                {
                case ReceiveStatus::idle:
                    if (chr == STX)
                    {
                        receive_status = ReceiveStatus::data;
                        received_lrc = 0;
                    }
                    break;
                case ReceiveStatus::data:
                    if (chr == ETX)
                    {
                        // Packet finished, process LRC
                        receive_status = ReceiveStatus::lrc;
                    }
                    break;
                case ReceiveStatus::lrc:
                    receive_status = ReceiveStatus::done;
                    if (received_lrc != 0)
                    {
                        // Tell someone that we had a problem
                        WRITE_LOG("Receive invalid LRC. Received %02x. Calculated %02x]", chr, received_lrc ^ chr);
                        receive_status = ReceiveStatus::error;
                    }
                    break;
                }
            }
        }

        // If we failed then NAK the terminal
        if (receive_status != ReceiveStatus::done)
        {
            WRITE_LOG("Send: %i/%c", NAK, NAK);
            uint8_t nak{ NAK };
            DWORD bytes_sent{ 0 };
            WriteFile(port_handle, &nak, sizeof(nak), &bytes_sent, NULL);

            return false;
        }
        else
        {
            // Tell the terminal that we received OK
            WRITE_LOG("Send: %i/%c", ACK, ACK);
            uint8_t ack{ ACK };
            DWORD bytes_sent{ 0 };
            WriteFile(port_handle, &ack, sizeof(ack), &bytes_sent, NULL);
        }

        // Extract the response
        std::string field;
        for (size_t i = 1; i < (data.size() - 2); i++)
        {
            if (data[i] == '|')
            {
                response.push_back(field);
                field.clear();
            }
            else
            {
                field.push_back(data[i]);
            }
        }
        response.push_back(field);

        return true;
    }

    static bool doit(const struct parameters &parameters, const std::vector<std::string> &request, std::vector<std::string> &response, std::stringstream &response_description, int ack_timeout_s, int command_timeout_s)
    {
        bool rc = false;
        HANDLE port_handle = open(parameters, 1024);
        if (!port_handle)
        {
            response_description << "Error abriendo puerto " << parameters.port;
            WRITE_LOG("Error opening port %s", parameters.port.c_str());
        }
        else if (!send(port_handle, request, ack_timeout_s))
        {
            response_description << "Error enviando datos al puerto " << parameters.port;
            WRITE_LOG("Error sending data to port %s", parameters.port.c_str());
        }
        else if (!recv(port_handle, response, command_timeout_s))
        {
            response_description << "Error recibiendo datos desde el puerto " << parameters.port;
            WRITE_LOG("Error receiving data from port %s", parameters.port.c_str());
        }
        else
        {
            rc = true;
        }
        close(port_handle);
        return rc;
    }
}

///json namespace implements the JSON API
namespace json
{
    static std::string pad(std::string value, size_t bytes, bool pad_left = false)
    {
        std::string value_str;
        if (value.length() < bytes)
        {
            value_str = value;
            if (pad_left)
            {
                value_str.insert(0, bytes - value_str.length(), '0');
            }
            else
            {
                value_str.insert(value_str.length(), bytes - value_str.length(), ' ');
            }
        }
        else if (value.length() > bytes)
        {
            value_str = value.substr(0, bytes);
        }
        else
        {
            value_str = value;
        }

        return value_str;
    }

    static std::string pad(int value, int bytes)
    {
        return pad(std::to_string(value), bytes, true);
    }

    static std::string pad(double value, int bytes)
    {
        return pad(std::to_string(value), bytes, true);
    }

    static int consulta_estado(const struct serialport::parameters &parameters, value &request, value &response)
    {
        // curl -H "Content-Type: application/json" -d '{}' http://localhost:8123/PinpadBridge/ConsultaEstado
        // {"ResponseCode":0,"ResponseDescription":"OK"}

        WRITE_LOG("%s starts", __FUNCTION__);
        write_log_json("request:", 0, request);

        std::vector<std::string> serialport_request = { "1010", "00", "01" };
        std::vector<std::string> serialport_response;
        std::stringstream serialport_response_description;
        int rc = serialport::doit(parameters, serialport_request, serialport_response, serialport_response_description, 10, 35);
        if (rc)
        {
            if ((serialport_response.size() == 1) && (serialport_response[0].length() == 1))
            {
                response["ResponseCode"] = (serialport_response[0][0] == ACK) ? 0 : -1;
                response["ResponseDescription"] = response["ResponseCode"] == 0 ? "OK" : "ERROR";
            }
            else
            {
                response["ResponseCode"] = -1;
                response["ResponseDescription"] = "Error en formato de respuesta";
            }
        }
        else
        {
            response["ResponseCode"] = -1;
            response["ResponseDescription"] = serialport_response_description.str();
        }

        write_log_json("response:", 0, response);
        WRITE_LOG("%s stops", __FUNCTION__);
        return response["ResponseCode"];
    }

    static int mensaje(const struct serialport::parameters &parameters, value &request, value &response)
    {
        // curl -H "Content-Type: application/json" -d '{"DisplayDuration":5,"Message": ["<----LINE 0---->","<----LINE 1---->","<----LINE 2---->","<----LINE 3---->"]}' http://localhost:8123/PinpadBridge/Mensaje
        // {"ResponseCode":0,"ResponseDescription":"OK"}

        WRITE_LOG("%s starts", __FUNCTION__);
        write_log_json("request:", 0, request);

        int display_duration = request["DisplayDuration"];
        int messages = min(static_cast<_array>(request["Message"]).size(), 4);
        std::vector<std::string> serialport_request =
        {
            "1020", display_duration == 0 ? "00" : "01", pad(display_duration, 2),
            pad(messages, 2),
            pad(messages > 0 ? static_cast<const char *>(static_cast<_array>(request["Message"])[0]) : "", 16),
            pad(messages > 1 ? static_cast<const char *>(static_cast<_array>(request["Message"])[1]) : "", 16),
            pad(messages > 2 ? static_cast<const char *>(static_cast<_array>(request["Message"])[2]) : "", 16),
            pad(messages > 3 ? static_cast<const char *>(static_cast<_array>(request["Message"])[3]) : "", 16)
        };
        std::vector<std::string> serialport_response;
        std::stringstream serialport_response_description;
        if (serialport::doit(parameters, serialport_request, serialport_response, serialport_response_description, 10, display_duration ? (display_duration + 1) : 60))
        {
            if (serialport_response.size() == 3)
            {
                response["ResponseCode"] = atoi(serialport_response[1].c_str());
                response["ResponseDescription"] = response["ResponseCode"] == 0 ? "OK" : "ERROR";
            }
            else
            {
                response["ResponseCode"] = -1;
                response["ResponseDescription"] = "Error en formato de respuesta";
            }
        }
        else
        {
            response["ResponseCode"] = -1;
            response["ResponseDescription"] = serialport_response_description.str();
        }

        write_log_json("response:", 0, response);
        WRITE_LOG("%s stops", __FUNCTION__);
        return response["ResponseCode"];
    }

    static int seleccion(const struct serialport::parameters &parameters, value &request, value &response)
    {
        // curl -H "Content-Type: application/json" -d '{"DisplayDuration":5,"ValueMaximum":2,"Message": ["<----LINE 0---->","<----LINE 1---->","<----LINE 2---->","<----LINE 3---->"]}' http://localhost:8123/PinpadBridge/Mensaje
        // {"Value":"01","ResponseCode":0,"ResponseDescription":"OK"}

        WRITE_LOG("%s starts", __FUNCTION__);
        write_log_json("request:", 0, request);

        int display_duration = request["DisplayDuration"];
        int messages = min(static_cast<_array>(request["Message"]).size(), 4);
        std::vector<std::string> serialport_request =
        {
            "1030", display_duration == 0 ? "00" : "01", pad(display_duration, 2),
            pad(messages, 2),
            pad(messages > 0 ? static_cast<const char *>(static_cast<_array>(request["Message"])[0]) : "", 16),
            pad(messages > 1 ? static_cast<const char *>(static_cast<_array>(request["Message"])[1]) : "", 16),
            pad(messages > 2 ? static_cast<const char *>(static_cast<_array>(request["Message"])[2]) : "", 16),
            pad(messages > 3 ? static_cast<const char *>(static_cast<_array>(request["Message"])[3]) : "", 16)
        };
        std::vector<std::string> serialport_response;
        std::stringstream serialport_response_description;
        if (serialport::doit(parameters, serialport_request, serialport_response, serialport_response_description, 10, display_duration ? (display_duration + 1) : 60))
        {
            if (serialport_response.size() == 4)
            {
                response["ResponseCode"] = atoi(serialport_response[1].c_str());
                response["ResponseDescription"] = response["ResponseCode"] == 0 ? "OK" : "ERROR";
                response["Value"] = response["ResponseCode"] == 0 ? serialport_response[2] : "";
            }
            else
            {
                response["ResponseCode"] = -1;
                response["ResponseDescription"] = "Error en formato de respuesta";
            }
        }
        else
        {
            response["ResponseCode"] = -1;
            response["ResponseDescription"] = serialport_response_description.str();
        }

        write_log_json("response:", 0, response);
        WRITE_LOG("%s stops", __FUNCTION__);
        return response["ResponseCode"];
    }

    static int lectura_tarjeta(const struct serialport::parameters &parameters, value &request, value &response)
    {
        // curl -H "Content-Type: application/json" -d '{"Store":0,"Amount":123400,"Currency":"CL","CardType":"CR"}' http://localhost:8123/PinpadBridge/LecturaTarjeta
        // {"CaptureType":"00","Track1":"...","Track2":"...","CardNumber":"...","CardHolderName":"...","CardTypeName":"...","CardTypeAbbreviation":"...","ResponseCode":0,"ResponseDescription":"OK"}

        WRITE_LOG("%s starts", __FUNCTION__);
        write_log_json("request:", 0, request);

        std::vector<std::string> serialport_request =
        {
            "1040",
            pad(static_cast<int>(request["Store"]), 2),
            pad(static_cast<const char *>(request["Amount"]), 18, true),
            static_cast<const char *>(request["Currency"]),
            static_cast<const char *>(request["CardType"])
        };
        std::vector<std::string> serialport_response;
        std::stringstream serialport_response_description;
        if (serialport::doit(parameters, serialport_request, serialport_response, serialport_response_description, 10, 35))
        {
            if (serialport_response.size() == 10)
            {
                response["ResponseCode"] = atoi(serialport_response[1].c_str());
                response["ResponseDescription"] = response["ResponseCode"] == 0 ? "OK" : "ERROR";
                response["CaptureType"] = serialport_response[2];
                response["Track1"] = serialport_response[3];
                response["Track2"] = serialport_response[4];
                response["CardNumber"] = serialport_response[5];
                response["CardHolderName"] = serialport_response[6];
                response["CardTypeName"] = serialport_response[7];
                response["CardTypeAbbreviation"] = serialport_response[8];
            }
            else
            {
                response["ResponseCode"] = -1;
                response["ResponseDescription"] = "Error en formato de respuesta";
            }
        }
        else
        {
            response["ResponseCode"] = -1;
            response["ResponseDescription"] = serialport_response_description.str();
        }

        write_log_json("response:", 0, response);
        WRITE_LOG("%s stops", __FUNCTION__);
        return response["ResponseCode"];
    }

    static int carga_llaves(const struct serialport::parameters &parameters, value &request, value &response)
    {
        // curl -H "Content-Type: application/json" -d '{"KeyNumber":0,"AuthenticationKey":"...","DataEncryptionKey":"...","DataEncryptionKeyII":"..."}' http://localhost:8123/PinpadBridge/CargaLlaves
        // {"ResponseCode":0,"ResponseDescription":"OK"}

        WRITE_LOG("%s starts", __FUNCTION__);
        write_log_json("request:", 0, request);

        std::vector<std::string> serialport_request =
        {
            "1050",
            static_cast<const char *>(request["KeyNumber"]),
            pad(static_cast<const char *>(request["AuthenticationKey"]), 32),
            pad(static_cast<const char *>(request["DataEncryptionKey"]), 32),
            pad(static_cast<const char *>(request["DataEncryptionKeyII"]), 32)
        };
        std::vector<std::string> serialport_response;
        std::stringstream serialport_response_description;
        if (serialport::doit(parameters, serialport_request, serialport_response, serialport_response_description, 10, 120))
        {
            if (serialport_response.size() == 10)
            {
                response["ResponseCode"] = atoi(serialport_response[1].c_str());
                response["ResponseDescription"] = response["ResponseCode"] == 0 ? "OK" : "ERROR";
            }
            else
            {
                response["ResponseCode"] = -1;
                response["ResponseDescription"] = "Error en formato de respuesta";
            }
        }
        else
        {
            response["ResponseCode"] = -1;
            response["ResponseDescription"] = serialport_response_description.str();
        }

        write_log_json("response:", 0, response);
        WRITE_LOG("%s stops", __FUNCTION__);
        return response["ResponseCode"];
    }

    static int lectura_pin(const struct serialport::parameters &parameters, value &request, value &response)
    {
		// Sin working key
		// curl -H "Content-Type: application/json" -d '{"PinLength":4,"PinBlockType":2,"Message":["<----LINE 1---->","<----LINE 1---->"]}' http://localhost:8123/PinpadBridge/LecturaPin
		// Con working key
		// curl -H "Content-Type: application/json" -d '{"PinLength":4,"PinBlockType":2,"WorkingKey":"DEADBEEF","Message":["<----LINE 1---->","<----LINE 1---->"]}' http://localhost:8123/PinpadBridge/LecturaPin
        // {"PinBlock":"...","KSN":"...","Other":"...","ResponseCode":0,"ResponseDescription":"OK"}

        WRITE_LOG("%s starts", __FUNCTION__);
        write_log_json("request:", 0, request);

        int messages = min(static_cast<_array>(request["Message"]).size(), 4);
        std::vector<std::string> serialport_request =
        {
            "1060",
            static_cast<const char *>(request["PinLength"]),
            static_cast<const char *>(request["PinBlockType"]),
            pad(request["WorkingKey"].is_null() ? "" : static_cast<const char *>(request["WorkingKey"]), 32),
            pad(messages > 0 ? static_cast<const char *>(static_cast<_array>(request["Message"])[0]) : "", 16),
            pad(messages > 1 ? static_cast<const char *>(static_cast<_array>(request["Message"])[1]) : "", 16),
        };
        std::vector<std::string> serialport_response;
        std::stringstream serialport_response_description;
        if (serialport::doit(parameters, serialport_request, serialport_response, serialport_response_description, 10, 120))
        {
            if (serialport_response.size() == 6)
            {
                response["ResponseCode"] = atoi(serialport_response[1].c_str());
                response["ResponseDescription"] = response["ResponseCode"] == 0 ? "OK" : "ERROR";
                response["PinBlock"] = serialport_response[2];
                response["KSN"] = serialport_response[3];
                response["Other"] = serialport_response[4];
            }
            else if (serialport_response.size() == 8)
			{
				response["ResponseCode"] = atoi(serialport_response[1].c_str());
				response["ResponseDescription"] = response["ResponseCode"] == 0 ? "OK" : "ERROR";
				response["PinBlock1"] = serialport_response[2];
				response["KSN1"] = serialport_response[3];
				response["PinBlock2"] = serialport_response[4];
				response["KSN2"] = serialport_response[5];
				response["Other"] = serialport_response[6];
			}
			else
			{
                response["ResponseCode"] = -1;
                response["ResponseDescription"] = "Error en formato de respuesta";
            }
        }
        else
        {
            response["ResponseCode"] = -1;
            response["ResponseDescription"] = serialport_response_description.str();
        }

        write_log_json("response:", 0, response);
        WRITE_LOG("%s stops", __FUNCTION__);
        return response["ResponseCode"];
    }
}

/// servicemanager namespace encapsulates the interaction with the Windows service manager to install/uninstall/start/stop a service.
namespace servicemanager
{
    class SERVICE_TYPE
    {
    public:
        typedef enum
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
        } type;
    };

    class SERVICE_START_TYPE
    {
    public:
        typedef enum
        {
            BOOT = SERVICE_BOOT_START,
            SYSTEM = SERVICE_SYSTEM_START,
            AUTO = SERVICE_AUTO_START,
            MANUAL = SERVICE_DEMAND_START,
            DISABLED = SERVICE_DISABLED
        } type;
    };

    class SERVICE_ERROR_TYPE
    {
    public:
        typedef enum
        {
            NONE = SERVICE_ERROR_IGNORE,
            NORMAL = SERVICE_ERROR_NORMAL,
            SEVERE = SERVICE_ERROR_SEVERE,
            CRITICAL = SERVICE_ERROR_CRITICAL
        } type;
    };

    static SC_HANDLE service_manager_handle = NULL;
    static SC_HANDLE service_handle = NULL;
    static std::string this_service_name;

    static void close()
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

    static int open_servicemanager()
    {
        if (service_manager_handle != NULL)
            return 0;

        service_manager_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (service_manager_handle == NULL)
            return -1;

        return 0;
    }

    static int open_service(const std::string &service_name)
    {
        // open a handle to the service manager
        if (open_servicemanager())
            return -1;

        // if we already have a handle to the service then check if it is our service 
        if (service_handle != NULL)
        {
            // if this is our service then we are done
            if (this_service_name == service_name)
                return 0;

            // not our service so clean up
            CloseServiceHandle(service_handle);
            service_handle = NULL;
            this_service_name.clear();
        }

        service_handle = OpenService(service_manager_handle, service_name.c_str(), SERVICE_ALL_ACCESS);
        this_service_name = service_name;

        return -(service_handle == NULL);
    }

    static DWORD query_service_status()
    {
        SERVICE_STATUS stat;
        if (!::QueryServiceStatus(service_handle, &stat))
            return -1;
        return stat.dwCurrentState;
    }

    static DWORD control_service(DWORD state)
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

    static int stop(const std::string &service_name)
    {
        if (open_service(service_name))
            return -1;

        if (query_service_status() != SERVICE_STOPPED)
        {
            if (control_service(SERVICE_STOP) != SERVICE_STOPPED)
            {
                do
                    Sleep(1000);
                while (query_service_status() == SERVICE_STOP_PENDING);
            }

            return -(query_service_status() != SERVICE_STOPPED);
        }
        else
            return 0;
    }

    static int start(const std::string &service_name)
    {
        if (open_service(service_name))
            return -1;

        switch (query_service_status())
        {
        case SERVICE_STOPPED:
            return -!StartService(service_handle, 0, NULL);
        case SERVICE_RUNNING:
            return 0;
        default:
            return -1;
        }
    }

    static int uninstall(const std::string &service_name)
    {
        if (open_service(service_name.c_str()))
            return -1;

        if (stop(service_name))
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

    static int install(const std::string &service_name, const std::string &display_name, const std::string &path, SERVICE_TYPE::type service_type, SERVICE_START_TYPE::type start_type, SERVICE_ERROR_TYPE::type error_control, const std::vector<std::string> &dependencies)
    {
        int rc = -1;

        if (open_servicemanager())
            return -1;

        if (service_handle != NULL)
        {
            CloseServiceHandle(service_handle);
            service_handle = NULL;
        }

        std::string dependencies_str;
        {
            std::stringstream ss;
            for (std::vector<std::string>::const_iterator i = dependencies.cbegin(); i != dependencies.cend(); i++)
            {
                ss << *i;
                ss << '\0';
            }

            // Make sure that it always has 2 nulls at the end
            ss << '\0';
            ss << '\0';

            // Store it
            dependencies_str = ss.str();
        }

        SC_HANDLE service_handle = CreateService(
            service_manager_handle,
            service_name.c_str(),
            display_name.c_str(),
            SERVICE_ALL_ACCESS,
            (DWORD)service_type,
            (DWORD)start_type,
            (DWORD)error_control,
            path.c_str(),
            NULL,
            NULL,
            dependencies_str.c_str(), // dependencies
            NULL,
            NULL
        );
        if (service_handle)
        {
            rc = 0;
        }
        else
        {
            DWORD error = GetLastError();
            write_log_system_error(__FILE__, __LINE__, __FUNCTION__, error);
        }

        return rc;
    }
}

/// service namespace encapsulates the interaction with the Windows service manager to start/stop a service that has already been registered.
namespace service
{
#define SERVICE_NAME "PindpadBridge2"
#define SERVICE_WAIT_HINT 10000

    SERVICE_STATUS			service_status;
    SERVICE_STATUS_HANDLE   service_status_handle;

    static void report_status(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
    {
        if (!service_status_handle)
            return;

        static DWORD dwCheckPoint = 1;

        // Fill in the SERVICE_STATUS structure.
        service_status.dwCurrentState = dwCurrentState;
        service_status.dwWin32ExitCode = dwWin32ExitCode;
        service_status.dwWaitHint = dwWaitHint;

        if (dwCurrentState == SERVICE_START_PENDING)
            service_status.dwControlsAccepted = 0;
        else
            service_status.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_STOP;

        if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
            service_status.dwCheckPoint = 0;
        else
            service_status.dwCheckPoint = dwCheckPoint++;

        // Report the status of the service to the SCM.
        SetServiceStatus(service_status_handle, &service_status);
    }

    static void stop();

    static DWORD __stdcall start(void *context);

    static void __stdcall ctrl_handler(DWORD ctrl)
    {
        // Handle the requested control code. 
        switch (ctrl)
        {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            report_status(SERVICE_STOP_PENDING, NO_ERROR, SERVICE_WAIT_HINT);

            // Signal the service to stop.
            stop();

            // update
            report_status(service_status.dwCurrentState, NO_ERROR, SERVICE_WAIT_HINT);
            return;
        case SERVICE_CONTROL_INTERROGATE:
            report_status(service_status.dwCurrentState, NO_ERROR, SERVICE_WAIT_HINT);
            break;

        default:
            report_status(service_status.dwCurrentState, ERROR_CALL_NOT_IMPLEMENTED, 0);
            break;
        }

    }

    static void __stdcall run(DWORD dwNumServicesArgs, LPSTR *lpServiceArgVectors)
    {
        WRITE_LOG("ServiceMain IN");

        service_status_handle = RegisterServiceCtrlHandler(TEXT(SERVICE_NAME), service::ctrl_handler);

        if (!service_status_handle)
        {
            WRITE_LOG("RegisterServiceCtrlHandler fails");
            return;
        }

        // These SERVICE_STATUS members remain as set here
        service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        service_status.dwServiceSpecificExitCode = 0;

        // Report initial status to the SCM
        report_status(SERVICE_START_PENDING, NO_ERROR, SERVICE_WAIT_HINT);

        // Perform service-specific initialization and work.
        HANDLE run_thread = CreateThread(NULL, 0, service::start, NULL, 0, NULL);
        if (run_thread)
        {
            WRITE_LOG("Service running on new thread");
            CloseHandle(run_thread);
        }
        else
        {
            WRITE_LOG("Error starting service thread");
            report_status(SERVICE_START_PENDING, NO_ERROR, SERVICE_WAIT_HINT);
        }

        WRITE_LOG("ServiceMain OUT");
    }
}

// read serial port parameters from the ini file
static void read_ini(struct serialport::parameters &parameters)
{
    char value[16];

    // Get the executable path
    char file_path[MAX_PATH];
    DWORD file_path_length = GetModuleFileName(NULL, file_path, sizeof(file_path));
    WRITE_LOG("Executable path=%s", file_path);

    // Create the ini path from the executable path
    char *ext = strrchr(file_path, '.');
    if (ext)
    {
        strcpy(ext, ".ini");
    }
    WRITE_LOG("Initialisation file path=%s", file_path);

    GET_PRIVATE_PROFILE_STRING("log", "file", "false", value, sizeof(value), file_path);
    if (!_stricmp(value, "true")) log_to_file = true;
    else log_to_file = false;

    // Read the INI file
    GET_PRIVATE_PROFILE_STRING("serialport", "port", "COM1", value, sizeof(value), file_path); parameters.port = value;
    GET_PRIVATE_PROFILE_STRING("serialport", "baudrate", "9600", value, sizeof(value), file_path); parameters.baudrate = atol(value);
    switch (parameters.baudrate)
    {
    case 110: case 300: case 600: case 1200: case 2400: case 4800: case 9600: case 14400:
    case 19200: case 38400: case 57600: case 115200: case 128000: case 256000:
        break;
    default:
        parameters.baudrate = 9600;
    }
    GET_PRIVATE_PROFILE_STRING("serialport", "databits", "8", value, sizeof(value), file_path); parameters.databits = atoi(value);
    if ((parameters.databits < 4) || (parameters.databits > 8)) parameters.databits = 8;
    GET_PRIVATE_PROFILE_STRING("serialport", "stopbits", "1", value, sizeof(value), file_path); parameters.stopbits = atof(value);
    switch (static_cast<int>(parameters.stopbits * 10))
    {
    case 10: case 15: case 20:
        break;
    default:
        parameters.stopbits = 1;
    }
    GET_PRIVATE_PROFILE_STRING("serialport", "parity", "none", value, sizeof(value), file_path);
    if (!_stricmp(value, "odd")) parameters.parity = 1;
    else if (!_stricmp(value, "even")) parameters.parity = 2;
    else if (!_stricmp(value, "mark")) parameters.parity = 3;
    else if (!_stricmp(value, "space")) parameters.parity = 4;
    else parameters.parity = 0;
    GET_PRIVATE_PROFILE_STRING("serialport", "flowcontrol", "none", value, sizeof(value), file_path);
    if (!_stricmp(value, "hardware")) parameters.flowcontrol = 1;
    else if (!_stricmp(value, "software")) parameters.flowcontrol = 2;
    else parameters.flowcontrol = 0;

    GET_PRIVATE_PROFILE_STRING("tcp", "port", "8123", value, sizeof(value), file_path); port = atoi(value);
    GET_PRIVATE_PROFILE_STRING("tcp", "recv_timeout", "10", value, sizeof(value), file_path); recv_timeout = atoi(value);
    GET_PRIVATE_PROFILE_STRING("tcp", "keep_alive", "0", value, sizeof(value), file_path); keep_alive = atoi(value);

    WRITE_LOG("log_to_file=%s", log_to_file ? "true" : "false");
    WRITE_LOG("tcp port=%i", port);
    WRITE_LOG("tcp recv_timeout=%i", recv_timeout);
    WRITE_LOG("tcp keep_alive=%i", keep_alive);
    WRITE_LOG("serial port=%s", parameters.port.c_str());
    WRITE_LOG("serial baudrate=%li", parameters.baudrate);
    WRITE_LOG("serial databits=%i", parameters.databits);
    WRITE_LOG("serial stopbits=%.1f", parameters.stopbits);
    WRITE_LOG("serial parity=%s", (parameters.parity == 0) ? "none" : (parameters.parity == 1) ? "odd" : (parameters.parity == 2) ? "even" : (parameters.parity == 3) ? "mark" : "space");
    WRITE_LOG("serial flowcontrol=%s", (parameters.flowcontrol == 0) ? "none" : (parameters.flowcontrol == 1) ? "hardware" : "software");
}

// REST API
static int http_204(struct soap *soap)
{
    if (soap->origin && soap->cors_method) /* CORS Origin and Access-Control-Request-Method headers */
    {
        if (soap->cors_allow)
        {
            soap->cors_origin = soap->origin; /* modify this code or hook your own soap->fopt() callback with logic */
        }
        soap->cors_methods = "GET, PUT, PATCH, POST, HEAD, OPTIONS";
        soap->cors_headers = soap->cors_header;
        soap->cors_allow_private_network = soap->cors_request_private_network;
        soap->keep_alive = keep_alive;
    }
    return soap_send_empty_response(soap, 204);
}

struct serialport::parameters parameters;

static DWORD __stdcall socket_thread_func(void *context)
{
    // Process the socket
    soap *ctx = static_cast<soap *>(context);
    SOCKADDR_IN addr = { 0 };
    socklen_t addr_len = sizeof(addr);
    getpeername(ctx->socket, (sockaddr *)&addr, &addr_len);
    WRITE_LOG("Open connection from %s:%i", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    value request(ctx), response(ctx);
    if (soap_begin_recv(ctx)
        || json_recv(ctx, request)
        || soap_end_recv(ctx))
    {
        std::stringstream ss;
        soap_stream_fault(ctx, ss);
        std::string fault_str = ss.str();
        WRITE_LOG("%s", fault_str.c_str());
    }
    else
    {
        int rc = 0;

        if (ctx->status == SOAP_POST)
        {
            if (!_stricmp(ctx->path, "/PinpadBridge/ConsultaEstado"))
            {
                json::consulta_estado(parameters, request, response);
            }
            else if (!_stricmp(ctx->path, "/PinpadBridge/Mensaje"))
            {
                json::mensaje(parameters, request, response);
            }
            else if (!_stricmp(ctx->path, "/PinpadBridge/Seleccion"))
            {
                json::seleccion(parameters, request, response);
            }
            else if (!_stricmp(ctx->path, "/PinpadBridge/LecturaTarjeta"))
            {
                json::lectura_tarjeta(parameters, request, response);
            }
            else if (!_stricmp(ctx->path, "/PinpadBridge/CargaLlaves"))
            {
                json::carga_llaves(parameters, request, response);
            }
            else if (!_stricmp(ctx->path, "/PinpadBridge/LecturaPin"))
            {
                json::lectura_pin(parameters, request, response);
            }
            else
            {
                WRITE_LOG("[%s] not found", ctx->path);
                rc = 404;
                response["ResponseCode"] = -1;
                response["ResponseDescription"] = "URI no existe";
            }
        }
        else
        {
            WRITE_LOG("Invalid HTTP METHOD. We only support POST", ctx->path);
            rc = 405;
            response["ResponseCode"] = -1;
            response["ResponseDescription"] = "Debe ser POST";
        }

        if (!response.has("ResponseCode") || !response.has("ResponseDescription"))
        {
            rc = -1;
            response["ResponseCode"] = -1;
            response["ResponseDescription"] = "ERROR";
        }

        // set http content type
        ctx->http_content = "application/json; charset=utf-8";
        ctx->keep_alive = keep_alive;
        if (ctx->cors_origin && (ctx->cors_origin[0] == '*'))
        {
            ctx->cors_origin = ctx->origin;
        }

        // send http header 200 OK and JSON response
        if (soap_response(ctx, SOAP_FILE + rc)
            || json_send(ctx, response)
            || soap_end_send(ctx))
        {
            std::stringstream ss;
            soap_stream_fault(ctx, ss);
            std::string fault_str = ss.str();
            WRITE_LOG("%s", fault_str.c_str());
        }
    }

    soap_closesock(ctx);
    WRITE_LOG("Close connection from %s:%i", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    return 0;
}

static int rest_api()
{
    // Read the ini file
    read_ini(parameters);

    // create an allocation context
    soap *ctx = soap_new1(SOAP_IO_KEEPALIVE | SOAP_C_UTFSTRING);
    // bind to port 
    if (!soap_valid_socket(soap_bind(ctx, NULL, port, 100)))
    {
        std::stringstream ss;
        soap_stream_fault(ctx, ss);
        std::string fault_str = ss.str();
        WRITE_LOG("%s", fault_str.c_str());
    }
    else
    {
        WRITE_LOG("Listening on 0.0.0.0:%i", port);
        register_gsoap_log_plugin(ctx);
        //ctx->recv_timeout = recv_timeout;
        ctx->fopt = http_204;

        // accept messages in server loop
        run = true;
        while (run)
        {
            fd_set rds;
            FD_ZERO(&rds);
            FD_SET(ctx->master, &rds);
            TIMEVAL tv;
            tv.tv_sec = 1; tv.tv_usec = 0;
            switch (select(FD_SETSIZE, &rds, NULL, NULL, &tv))
            {
            case -1:
                WRITE_LOG("Error waiting for connection");
                run = false;
            case 0:
                // No connection
                continue;
            }
            if (!soap_valid_socket(soap_accept(ctx)))
            {
                std::stringstream ss;
                soap_stream_fault(ctx, ss);
                std::string fault_str = ss.str();
                WRITE_LOG("%s", fault_str.c_str());
                run = false;
            }
            else
            {
                // Perform service-specific initialization and work.
                HANDLE socket_thread = CreateThread(NULL, 0, socket_thread_func, soap_copy(ctx), 0, NULL);
                if (socket_thread)
                {
                    WRITE_LOG("socket running on new thread");
                    CloseHandle(socket_thread);
                }
                else
                {
                    WRITE_LOG("Error starting socket thread");
                }
            }

            // dealloc all
            soap_destroy(ctx);
            soap_end(ctx);
        }
    }
    // free context
    soap_free(ctx);

    return 0;
}

// stop function required by the service namespace
static void service::stop()
{
    ::run = false;
}

// start function required by the service namespace
static DWORD __stdcall service::start(void *context)
{
    DWORD rc = 0;

    // Tell service manager that we are running
    report_status(SERVICE_RUNNING, NO_ERROR, SERVICE_WAIT_HINT);

    // Run the service
    rc = rest_api();

    // Tell the service manager that we have stopped
    report_status(SERVICE_STOPPED, NO_ERROR, 0);
    return rc;
}

// print help message
static void help()
{
    WRITE_LOG("Syntax: PinpadBridge2 [/{d | i | u}]");
    WRITE_LOG("-> Sin parámetros iniciará PinpadBridge2 dentro del manejador de servicios de Windows.");
    WRITE_LOG("-> /d iniciará PinpadBridge2 como un ejecutable de línea de comandos de Windows.");
    WRITE_LOG("-> /i registrará PindpadBridge2 con el manejador de servicios de Windows.");
    WRITE_LOG("-> /u eliminará el registro de PindpadBridge2 desde el manejador de servicios de Windows.");
}

static BOOL WINAPI ctrl_handler(DWORD fdwCtrlType)
{
    if (fdwCtrlType == CTRL_C_EVENT)
    {
        WRITE_LOG("Stop requested by user.");
        run = false;
        return TRUE;
    }

    return FALSE;
}

int main(int argc, char *argv[], char *envp[])
{
    int rc = -1;
    if (argc == 1)
    {
        char service_name[] = SERVICE_NAME;
        SERVICE_TABLE_ENTRY DispatchTable[] =
        {
            { service_name, service::run },
            { NULL, NULL }
        };

        // This call returns when the service has stopped. 
        // The process should simply terminate when the call returns.
        if (!StartServiceCtrlDispatcher(DispatchTable))
        {
            WRITE_LOG("StartServiceCtrlDispatcher fails");
        }
    }
    else if (argc == 2)
    { 
        if (!_stricmp(argv[1], "/d"))
        {
            // Register for Ctrl-C
            WRITE_LOG("Presione Ctrl-C para detener.");
            SetConsoleCtrlHandler(ctrl_handler, TRUE);

            // Run
            rc = rest_api();
        }
        else if (!_stricmp(argv[1], "/i"))
        {
            // Install service
            char file_path[MAX_PATH];
            DWORD file_path_length = GetModuleFileName(NULL, file_path, sizeof(file_path));
            std::vector<std::string> dependencies;
            rc = servicemanager::install(SERVICE_NAME, SERVICE_NAME, file_path, servicemanager::SERVICE_TYPE::WIN32_OWN_PROCESS, servicemanager::SERVICE_START_TYPE::AUTO, servicemanager::SERVICE_ERROR_TYPE::NORMAL, dependencies);
            if (rc)
            {
                WRITE_LOG("Error installing service %s", SERVICE_NAME);
            }
            else
            {
                WRITE_LOG("Service %s installed correctly", SERVICE_NAME);
            }
        }
        else if (!_stricmp(argv[1], "/u"))
        {
            rc = servicemanager::uninstall(SERVICE_NAME);
            if (rc)
            {
                WRITE_LOG("Error uninstalling service %s", SERVICE_NAME);
            }
            else
            {
                WRITE_LOG("Service %s uninstalled correctly", SERVICE_NAME);
            }
        }
        else
        {
            help();
        }
    }
    else
    {
        help();
    }
    return rc;
}
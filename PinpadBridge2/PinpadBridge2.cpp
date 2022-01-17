// PinpadBridge2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "soapH.h"
#include "json.h"

#include <vector>
#include <string>

#include <stdio.h>
#include <stdarg.h>

#define WRITE_LOG(...) write_log(__FILE__, __LINE__, __VA_ARGS__)

#define STX 0x02
#define ETX 0x03
#define ACK 0x06
#define NAK 0x15

/* Don't need a namespace table. We put an empty one here to avoid link errors */
struct Namespace namespaces[] = { {NULL, NULL} };

void write_log(const char *file, int line, const char *format, ...)
{
    // local data
    va_list arg;
    time_t log_time;
    char date_stamp[9], time_stamp[9];
    
    const char *p = strrchr(file, '\\');
    if (p)
        file = p + 1;

    // get the time stamps
    log_time = time(0);
    strftime(time_stamp, sizeof(time_stamp), "%H:%M:%S", localtime(&log_time));
    strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", localtime(&log_time));

    // log to standard error
    fprintf(stderr, "%s@%s [%s@%05i] ", date_stamp, time_stamp, file, line);
    va_start(arg, format);
    vfprintf(stderr, format, arg);
    va_end(arg);
    fprintf(stderr, "\n");
}

void write_log_system_error(const char *file, int line, const std::string &prompt, DWORD error)
{
    char *message;
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, error, 0, (LPSTR)&message, 0, NULL);
    if (message)
    {
        write_log(file, line, "%s: %s", prompt.c_str(), message);
        LocalFree(message);
    }
    else
    {
        write_log(file, line, "%s", prompt.c_str());
    }
}

void write_log_json(const char *prompt, int indent, value &v)
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

HANDLE serialport_open(const std::string &port, long baudrate, int databits, double stopbits, int parity, DWORD buffer_size, bool rts_cts, bool xon_xoff)
{
    // local data
    HANDLE			port_handle = NULL;
    std::string     port_path = std::string("\\\\.\\") + port;
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
        write_log_system_error(__FILE__, __LINE__, std::string("Error opening port ") + port.c_str(), GetLastError());
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
    switch (baudrate)
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
    dcb.ByteSize = (unsigned char)databits;

    // set the stop bits
    switch (static_cast<int>(stopbits * 10))
    {
    case 10: dcb.StopBits = ONESTOPBIT; break;
    case 15: dcb.StopBits = ONE5STOPBITS; break;
    case 20: dcb.StopBits = TWOSTOPBITS; break;
    }

    // set the parity
    switch (parity)
    {
    case 0: dcb.Parity = NOPARITY; break;
    case 1: dcb.Parity = ODDPARITY; break;
    case 2: dcb.Parity = EVENPARITY; break;
    case 3: dcb.Parity = MARKPARITY; break;
    case 4: dcb.Parity = SPACEPARITY; break;
    }
    dcb.fParity = parity ? TRUE : FALSE;

    // disable DTR/DSR hardware flow control
    dcb.fDtrControl = DTR_CONTROL_DISABLE;
    dcb.fOutxDsrFlow = FALSE;

    // if RTS/CTS flow control enabled then ...
    if (rts_cts)
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
    if (xon_xoff)
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

void serialport_close(HANDLE &port_handle)
{
    if (port_handle)
    {
        CloseHandle(port_handle);
        port_handle = NULL;
    }
}

DWORD serialport_wait(HANDLE port_handle, int timeout_s)
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

bool serialport_send(HANDLE port_handle, const std::vector<std::string> &request, int ack_timeout_s)
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
    if (!serialport_wait(port_handle, ack_timeout_s))
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

bool serialport_recv(HANDLE port_handle, std::vector<std::string> &response, int command_timeout_s)
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
            case lrc: return "lrc";
            case done: return "done";
            }
            return "UNKNOWN";
        }
    };
    ReceiveStatus::type receive_status = ReceiveStatus::idle;
    std::vector<uint8_t> data;
    uint8_t received_lrc;

    while ((receive_status != ReceiveStatus::done) && (receive_status != ReceiveStatus::error) && serialport_wait(port_handle, command_timeout_s))
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

bool serialport_doit(const std::string port, const std::vector<std::string> &request, std::vector<std::string> &response, int ack_timeout_s, int command_timeout_s)
{
    bool rc = false;
    HANDLE port_handle = serialport_open(port, 115200, 8, 1, 0, 1024, false, false);
    if (!port_handle)
    {
        WRITE_LOG("Error opening port %s", port.c_str());
    }
    else if (!serialport_send(port_handle, request, ack_timeout_s))
    {
        WRITE_LOG("Error sending data to port %s", port.c_str());
    }
    else if (!serialport_recv(port_handle, response, command_timeout_s))
    {
        WRITE_LOG("Error receiving data from port %s", port.c_str());
    }
    else
    {
        rc = true;
    }
    serialport_close(port_handle);
    return rc;
}

int consulta_estado(value &request, value &response)
{
    // curl -X POST -H "Content-Type: application/json" -d '{}' http://localhost:8123/PinpadBridge/ConsultaEstado
    // {"ResponseCode":0,"ResponseDescription":"OK"}

    WRITE_LOG("%s starts", __FUNCTION__);
    write_log_json("request:", 0, request);

    std::vector<std::string> serialport_request = { "1010", "00", "01" };
    std::vector<std::string> serialport_response;
    if (serialport_doit("COM1", serialport_request, serialport_response, 10, 35))
    {
        if ((serialport_response.size() == 1) && (serialport_response[0].length() == 1))
        {
            response["ResponseCode"] = (serialport_response[0][0] == ACK) ? 0 : -1;
        }
        else
        {
            response["ResponseCode"] = -1;
        }
    }
    else
    {
        response["ResponseCode"] = -1;
    }
    response["ResponseDescription"] = response["ResponseCode"] == 0 ? "OK" : "ERROR";

    write_log_json("response:", 0, response);
    WRITE_LOG("%s stops", __FUNCTION__);
    return response["ResponseCode"];
}

std::string pad(std::string value, size_t bytes, bool pad_left = false)
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

std::string pad(int value, int bytes)
{
    return pad(std::to_string(value), bytes, true);
}

std::string pad(double value, int bytes)
{
    return pad(std::to_string(value), bytes, true);
}

int mensaje(value &request, value &response)
{
    // curl -X POST -H "Content-Type: application/json" -d '{"DisplayDuration":5,"Message": ["<----LINE 0---->","<----LINE 1---->","<----LINE 2---->","<----LINE 3---->"]}' http://localhost:8123/PinpadBridge/Mensaje
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
    if (serialport_doit("COM1", serialport_request, serialport_response, 10, display_duration ? (display_duration + 1) : 60))
    {
        if (serialport_response.size() == 3)
        {
            response["ResponseCode"] = atoi(serialport_response[1].c_str());
        }
        else
        {
            response["ResponseCode"] = -1;
        }
    }
    else
    {
        response["ResponseCode"] = -1;
    }
    response["ResponseDescription"] = response["ResponseCode"] == 0 ? "OK" : "ERROR";

    write_log_json("response:", 0, response);
    WRITE_LOG("%s stops", __FUNCTION__);
    return response["ResponseCode"];
}

int seleccion(value &request, value &response)
{
    // curl -X POST -H "Content-Type: application/json" -d '{"DisplayDuration":5,"ValueMaximum":2,"Message": ["<----LINE 0---->","<----LINE 1---->","<----LINE 2---->","<----LINE 3---->"]}' http://localhost:8123/PinpadBridge/Mensaje
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
    if (serialport_doit("COM1", serialport_request, serialport_response, 10, display_duration ? (display_duration + 1) : 60))
    {
        if (serialport_response.size() == 4)
        {
            response["ResponseCode"] = atoi(serialport_response[1].c_str());
            response["Value"] = response["ResponseCode"] == 0 ? serialport_response[2] : "";
        }
        else
        {
            response["ResponseCode"] = -1;
        }
    }
    else
    {
        response["ResponseCode"] = -1;
    }
    response["ResponseDescription"] = response["ResponseCode"] == 0 ? "OK" : "ERROR";

    write_log_json("response:", 0, response);
    WRITE_LOG("%s stops", __FUNCTION__);
    return response["ResponseCode"];
}

int lectura_tarjeta(value &request, value &response)
{
    // curl -X POST -H "Content-Type: application/json" -d '{"Store":0,"Amount":123400,"Currency":"CL","CardType":"CR"}' http://localhost:8123/PinpadBridge/LecturaTarjeta
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
    if (serialport_doit("COM1", serialport_request, serialport_response, 10, 35))
    {
        if (serialport_response.size() == 10)
        {
            response["ResponseCode"] = atoi(serialport_response[1].c_str());
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
        }
    }
    else
    {
        response["ResponseCode"] = -1;
    }
    response["ResponseDescription"] = response["ResponseCode"] == 0 ? "OK" : "ERROR";

    write_log_json("response:", 0, response);
    WRITE_LOG("%s stops", __FUNCTION__);
    return response["ResponseCode"];
}

int carga_llaves(value &request, value &response)
{
    // curl -X POST -H "Content-Type: application/json" -d '{"KeyNumber":0,"AuthenticationKey":"...","DataEncryptionKey":"...","DataEncryptionKeyII":"..."}' http://localhost:8123/PinpadBridge/CargaLlaves
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
    if (serialport_doit("COM1", serialport_request, serialport_response, 10, 120))
    {
        if (serialport_response.size() == 10)
        {
            response["ResponseCode"] = atoi(serialport_response[1].c_str());
        }
        else
        {
            response["ResponseCode"] = -1;
        }
    }
    else
    {
        response["ResponseCode"] = -1;
    }
    response["ResponseDescription"] = response["ResponseCode"] == 0 ? "OK" : "ERROR";

    write_log_json("response:", 0, response);
    WRITE_LOG("%s stops", __FUNCTION__);
    return response["ResponseCode"];
}

int lectura_pin(value &request, value &response)
{
    // curl -X POST -H "Content-Type: application/json" -d '{"PinLength":4,"WorkingKey":null,"Message":["<----LINE 1---->","<----LINE 1---->"]}' http://localhost:8123/PinpadBridge/LecturaPin
    // {"PinBlock":"...","ResponseCode":0,"ResponseDescription":"OK"}

    WRITE_LOG("%s starts", __FUNCTION__);
    write_log_json("request:", 0, request);

    int messages = min(static_cast<_array>(request["Message"]).size(), 4);
    std::vector<std::string> serialport_request =
    {
        "1060",
        static_cast<const char *>(request["PinLength"]),
        strlen(static_cast<const char *>(request["WorkingKey"])) ? "1" : "0",
        pad(static_cast<const char *>(request["WorkingKey"]), 32),
        pad(messages > 0 ? static_cast<const char *>(static_cast<_array>(request["Message"])[0]) : "", 16),
        pad(messages > 1 ? static_cast<const char *>(static_cast<_array>(request["Message"])[1]) : "", 16),
    };
    std::vector<std::string> serialport_response;
    if (serialport_doit("COM1", serialport_request, serialport_response, 10, 120))
    {
        if (serialport_response.size() == 10)
        {
            response["ResponseCode"] = atoi(serialport_response[1].c_str());
            response["PinBlock"] = serialport_response[2];
        }
        else
        {
            response["ResponseCode"] = -1;
        }
    }
    else
    {
        response["ResponseCode"] = -1;
    }
    response["ResponseDescription"] = response["ResponseCode"] == 0 ? "OK" : "ERROR";

    write_log_json("response:", 0, response);
    WRITE_LOG("%s stops", __FUNCTION__);
    return response["ResponseCode"];
}

int main()
{
    // create an allocation context
    soap *ctx = soap_new1(SOAP_IO_KEEPALIVE | SOAP_C_UTFSTRING);
    // bind to port 8123
    if (!soap_valid_socket(soap_bind(ctx, NULL, 8123, 100)))
        soap_print_fault(ctx, stderr);
    else
    {
        // accept messages in server loop
        for (;;)
        {
            if (!soap_valid_socket(soap_accept(ctx)))
                soap_print_fault(ctx, stderr);
            else
            {
                value request(ctx), response(ctx);
                if (soap_begin_recv(ctx)
                    || json_recv(ctx, request)
                    || soap_end_recv(ctx))
                {
                    json_send_fault(ctx); // return a JSON-formatted fault
                }
                else
                {
                    int rc = 404;

                    if (!_stricmp(ctx->path, "/PinpadBridge/ConsultaEstado"))
                    {
                        rc = consulta_estado(request, response);
                    }
                    else if (!_stricmp(ctx->path, "/PinpadBridge/Mensaje"))
                    {
                        mensaje(request, response);
                    }
                    else if (!_stricmp(ctx->path, "/PinpadBridge/Seleccion"))
                    {
                        seleccion(request, response);
                    }
                    else if (!_stricmp(ctx->path, "/PinpadBridge/LecturaTarjeta"))
                    {
                        lectura_tarjeta(request, response);
                    }
                    else if (!_stricmp(ctx->path, "/PinpadBridge/CargaLlaves"))
                    {
                        carga_llaves(request, response);
                    }
                    else if (!_stricmp(ctx->path, "/PinpadBridge/LecturaPin"))
                    {
                        lectura_pin(request, response);
                    }
                    else
                    {
                        WRITE_LOG("[%s] not found", ctx->path);
                    }

                    if (!response.has("ResponseCode") || !response.has("ResponseDescription"))
                    {
                        response["ResponseCode"] = -1;
                        response["ResponseDescription"] = "ERROR";
                    }

                    // set http content type
                    ctx->http_content = "application/json; charset=utf-8";
                    ctx->http_extra_header =
                        "Access-Control-Allow-Origin: *\r\n"
                        "Access-Control-Allow-Credentials: true\r\n"
                        "Access-Control-Allow-Headers: Origin, Content-Type, Accept, Authorization\r\n"
                        "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, HEAD"
                        ;
                    ctx->keep_alive = false;

                    // send http header 200 OK and JSON response
                    if (soap_response(ctx, SOAP_FILE + rc)
                        || json_send(ctx, response)
                        || soap_end_send(ctx))
                        json_send_fault(ctx);
                    soap_closesock(ctx);
                }

                // dealloc all
                soap_destroy(ctx);
                soap_end(ctx);
            }
        }
    }
    // free context
    soap_free(ctx);
}

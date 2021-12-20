#include "pch.h"
#include "Utils.h"

#include <stdio.h>

void write_log(const char *file, int line, DWORD last_error, const char *format, ...)
{
    va_list args0, args1;
    char timestamp[20];
    time_t now;
    char *buffer = NULL, *error_buffer = NULL;
    size_t buffer_size;

    // create the time stamp
    now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // get the argument list and a copý. Windows doesn't have va_copy so just copy the pointer.
    va_start(args0, format);
    args1 = args0;

    // Retrieve the system error message for the last-error code
    if (last_error)
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            last_error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&error_buffer,
            0, NULL);

    // calculate the buffer length: prompt + message + [error message] + line end (<cr><lf><nul>)
    buffer_size =
        (file ? _snprintf(NULL, 0, "%s %s:%i ", timestamp, file, line) : _snprintf(NULL, 0, "%s ", timestamp)) +
        _vsnprintf(NULL, 0, format, args0) +
        (last_error ? _snprintf(NULL, 0, " failed with error %d: %s", last_error, error_buffer) : 0) +
        1;

    // create the buffer
    buffer = (char *)malloc(buffer_size);

    // actually print
    if (buffer)
    {
        size_t buffer_length = 0;

        buffer_length += file ? _snprintf(buffer, buffer_size, "%s %s:%i ", timestamp, file, line) : _snprintf(buffer, buffer_size, "%s ", timestamp);
        buffer_length += _vsnprintf(&buffer[buffer_length], buffer_size - buffer_length, format, args1);
        buffer_length += last_error ? _snprintf(&buffer[buffer_length], buffer_size - buffer_length, " failed with error %d: %s", last_error, error_buffer) : 0;

        printf("%s\r\n", buffer);

        free(buffer);
    }

    // release the variable arguments
    va_end(args0);

    // free the error message
    if (error_buffer)
        LocalFree(error_buffer);
}

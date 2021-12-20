#pragma once
#define WRITE_LOG(last_error, fmt, ...) write_log(__FILE__, __LINE__, last_error, fmt, __VA_ARGS__) 
void write_log(const char *file, int line, DWORD last_error, const char *format, ...);

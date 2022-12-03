#pragma once

#include <Windows.h>
#include <iostream>
#include <stdio.h>

#ifndef xor
#define xor
#endif // !xor

#define __Ok(message, ...) Log::Ok(xor(message), __VA_ARGS__)
#define __Info(message, ...) Log::Info(xor(message), __VA_ARGS__)
#define __Warn(message, ...) Log::Warn(xor(message), __VA_ARGS__)
#define __Err(message, ...) Log::Err(xor(message), __VA_ARGS__)

#define RESET_COLOR 15
#define OK_COLOR 10
#define INFO_COLOR 11
#define WARN_COLOR 14
#define ERROR_COLOR 4

enum LogLevel
{
    Full,     // Errors, Warnings, Success, Info
    Medium,   // Errors, Warnings, Success
    Strict,   // Errors, Warnings
    Critical, // Errors
    None,      // Guess...
};

inline LogLevel logLevel;

class Log
{
private:
    static inline HANDLE _hStdOut;
    static inline bool _bIsStdInitialized;

public:

    static void SetLogLevel(LogLevel level = LogLevel::Full) { logLevel = level; }

    static void InitStdOutHandle() {
        Log::_hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (Log::_hStdOut) Log::_bIsStdInitialized = true;
    }

#ifdef _WINDLL
    static void AllocConsoleWithTitle(std::string title)
    {

        _iobuf* buf;
        if (AllocConsole())
            freopen_s(&buf, xor ("CONOUT$"), xor ("w"), stdout);

        SetConsoleTitleA(title.c_str());
    }
#else
    static void SetTitle(std::string title) { SetConsoleTitleA(title.c_str()); }
#endif


    static void Ok(std::string format, ...) {
        if (logLevel != LogLevel::Full && logLevel != LogLevel::Medium) return;
        va_list args;
        va_start(args, format);
        if (Log::_bIsStdInitialized) {
            std::cout << xor ("[");
            SetConsoleTextAttribute(Log::_hStdOut, OK_COLOR);
            std::cout << xor ("+");
            SetConsoleTextAttribute(Log::_hStdOut, RESET_COLOR);
            _vfprintf_l(stdout, ("] " + format + "\n").c_str(), NULL, args);
        }
        else _vfprintf_l(stdout, std::string(xor ("[+] ")).append(format + "\n").c_str(), NULL, args);
        va_end(args);
    }

    static void Info(std::string format, ...) {
        if (logLevel != LogLevel::Full) return;
        va_list args;
        va_start(args, format);
        if (Log::_bIsStdInitialized) {
            std::cout << xor ("[");
            SetConsoleTextAttribute(Log::_hStdOut, INFO_COLOR);
            std::cout << xor ("~");
            SetConsoleTextAttribute(Log::_hStdOut, RESET_COLOR);
            _vfprintf_l(stdout, ("] " + format + "\n").c_str(), NULL, args);
        }
        else _vfprintf_l(stdout, std::string(xor ("[~] ")).append(format + "\n").c_str(), NULL, args);
        va_end(args);
    }

    static void Warn(std::string format, ...) {
        if (logLevel == LogLevel::Critical || logLevel == LogLevel::None) return;
        va_list args;
        va_start(args, format);
        if (Log::_bIsStdInitialized) {
            std::cout << xor ("[");
            SetConsoleTextAttribute(Log::_hStdOut, WARN_COLOR);
            std::cout << xor ("!");
            SetConsoleTextAttribute(Log::_hStdOut, RESET_COLOR);
            _vfprintf_l(stdout, ("] " + format + "\n").c_str(), NULL, args);
        }
        else _vfprintf_l(stdout, std::string(xor ("[!] ")).append(format + "\n").c_str(), NULL, args);
        va_end(args);
    }

    static void Err(std::string format, ...) {
        if (logLevel == LogLevel::None) return;
        va_list args;
        va_start(args, format);
        if (Log::_bIsStdInitialized) {
            std::cout << xor ("[");
            SetConsoleTextAttribute(Log::_hStdOut, ERROR_COLOR);
            std::cout << xor ("-");
            SetConsoleTextAttribute(Log::_hStdOut, RESET_COLOR);
            _vfprintf_l(stdout, ("] " + format + "\n").c_str(), NULL, args);
        }
        else _vfprintf_l(stdout, std::string(xor ("[-] ")).append(format + "\n").c_str(), NULL, args);
        va_end(args);
    }
};

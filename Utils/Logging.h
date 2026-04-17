#pragma once

#include <stdio.h>

#define Log(lvl, fmt, ...) LogMessage(LogLevel::##lvl, fmt, ##__VA_ARGS__)

enum class LogLevel
{
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
};

void
LogMessage(
    LogLevel level,
    const char* fmt,
    ...);

void SetLogLevel(LogLevel lvl);

// Returns FALSE when running on 24H2 (26100) or later
#define IsFixedVersion() (USER_SHARED_DATA->NtBuildNumber >= 26100)


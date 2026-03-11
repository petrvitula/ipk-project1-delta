#pragma once

#include <atomic>

// Global flag indicating a request to terminate the program (SIGINT/SIGTERM)
extern std::atomic<bool> gTerminate;

// Register signal handlers for SIGINT and SIGTERM
void setupSignalHandlers();


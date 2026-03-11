#include "SignalHandler.h"

#include <csignal>

std::atomic<bool> gTerminate{false};

namespace {

void signalHandler(int)
{
    gTerminate.store(true);
}

} // namespace

void setupSignalHandlers()
{
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
}


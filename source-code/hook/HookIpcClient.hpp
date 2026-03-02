#pragma once
#include <string>
#include "shared/GuardProtocol.hpp"

namespace guard::hook
{
    // Returns true if allowed; false if denied (and sets LastError).
    bool DecideOrDeny(const guard::proto::GuardRequest& req);

    // Helper for logging/debug: returns service message if available.
    std::wstring LastServiceMessage();
}


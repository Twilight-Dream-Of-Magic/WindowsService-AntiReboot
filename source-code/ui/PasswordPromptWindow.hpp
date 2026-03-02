#pragma once
#include <string>

namespace guard::ui
{
    struct PromptResult
    {
        bool approved = false;
        std::wstring password;
    };

    // Minimal Win32 password prompt (topmost).
    class PasswordPromptWindow
    {
    public:
        static PromptResult Prompt(const std::wstring& title, const std::wstring& message, unsigned timeoutMs);
    };
}


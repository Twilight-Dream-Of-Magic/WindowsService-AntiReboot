#include "PasswordPromptWindow.hpp"

#include <windows.h>
#include <commctrl.h>
#include <string>

#include "shared/GuardProtocol.hpp"

namespace guard::ui
{
    namespace
    {
        constexpr wchar_t kWndClass[] = L"ShutdownGuard_PasswordPrompt";
        constexpr UINT_PTR kTimerId = 1;

        struct State
        {
            PromptResult result{};
            std::wstring title;
            std::wstring message;
            unsigned remainingMs = 0;

            HWND hwnd = nullptr;
            HWND hEdit = nullptr;
            HWND hCountdown = nullptr;
        };

        void CenterWindow(HWND hwnd)
        {
            RECT rc{};
            GetWindowRect(hwnd, &rc);
            int w = rc.right - rc.left;
            int h = rc.bottom - rc.top;
            int sw = GetSystemMetrics(SM_CXSCREEN);
            int sh = GetSystemMetrics(SM_CYSCREEN);
            int x = (sw - w) / 2;
            int y = (sh - h) / 2;
            SetWindowPos(hwnd, HWND_TOPMOST, x, y, 0, 0, SWP_NOSIZE | SWP_SHOWWINDOW);
        }

        std::wstring SecondsText(unsigned ms)
        {
            unsigned sec = (ms + 999) / 1000;
            return L"剩余时间: " + std::to_wstring(sec) + L"s";
        }

        LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
        {
            auto* st = reinterpret_cast<State*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

            switch (msg)
            {
            case WM_CREATE:
            {
                auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
                st = reinterpret_cast<State*>(cs->lpCreateParams);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(st));
                st->hwnd = hwnd;

                const int pad = 12;
                const int w = 460;
                const int h = 200;
                SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, w, h, SWP_NOMOVE);

                CreateWindowExW(0, L"STATIC", st->message.c_str(),
                    WS_CHILD | WS_VISIBLE,
                    pad, pad, w - pad * 2, 60,
                    hwnd, nullptr, nullptr, nullptr);

                st->hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL,
                    pad, 80, w - pad * 2, 26,
                    hwnd, reinterpret_cast<HMENU>(1001), nullptr, nullptr);

                st->hCountdown = CreateWindowExW(0, L"STATIC", SecondsText(st->remainingMs).c_str(),
                    WS_CHILD | WS_VISIBLE,
                    pad, 112, w - pad * 2, 20,
                    hwnd, nullptr, nullptr, nullptr);

                CreateWindowExW(0, L"BUTTON", L"允许",
                    WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                    w - pad * 2 - 180, 140, 80, 28,
                    hwnd, reinterpret_cast<HMENU>(IDOK), nullptr, nullptr);

                CreateWindowExW(0, L"BUTTON", L"拒绝",
                    WS_CHILD | WS_VISIBLE,
                    w - pad * 2 - 90, 140, 80, 28,
                    hwnd, reinterpret_cast<HMENU>(IDCANCEL), nullptr, nullptr);

                SetFocus(st->hEdit);
                SetTimer(hwnd, kTimerId, 250, nullptr);
                CenterWindow(hwnd);
                return 0;
            }
            case WM_TIMER:
                if (wParam == kTimerId && st)
                {
                    if (st->remainingMs <= 250)
                    {
                        st->result.approved = false;
                        if (!st->result.password.empty())
                            SecureZeroMemory(st->result.password.data(), st->result.password.size() * sizeof(wchar_t));
                        st->result.password.clear();
                        DestroyWindow(hwnd);
                        return 0;
                    }
                    st->remainingMs -= 250;
                    SetWindowTextW(st->hCountdown, SecondsText(st->remainingMs).c_str());
                }
                return 0;
            case WM_COMMAND:
                if (!st) break;
                switch (LOWORD(wParam))
                {
                case IDOK:
                {
                    wchar_t buf[guard::proto::kMaxText] = {};
                    GetWindowTextW(st->hEdit, buf, static_cast<int>(std::size(buf)));
                    st->result.approved = true;
                    st->result.password = buf;
                    SecureZeroMemory(buf, sizeof(buf));
                    DestroyWindow(hwnd);
                    return 0;
                }
                case IDCANCEL:
                    st->result.approved = false;
                    if (!st->result.password.empty())
                        SecureZeroMemory(st->result.password.data(), st->result.password.size() * sizeof(wchar_t));
                    st->result.password.clear();
                    DestroyWindow(hwnd);
                    return 0;
                default:
                    break;
                }
                break;
            case WM_CLOSE:
                if (st)
                {
                    st->result.approved = false;
                    if (!st->result.password.empty())
                        SecureZeroMemory(st->result.password.data(), st->result.password.size() * sizeof(wchar_t));
                    st->result.password.clear();
                }
                DestroyWindow(hwnd);
                return 0;
            case WM_DESTROY:
                KillTimer(hwnd, kTimerId);
                return 0;
            default:
                break;
            }
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        }

        ATOM EnsureClass()
        {
            static ATOM atom = 0;
            if (atom) return atom;
            WNDCLASSEXW wc{};
            wc.cbSize = sizeof(wc);
            wc.lpfnWndProc = WndProc;
            wc.hInstance = GetModuleHandleW(nullptr);
            wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
            wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
            wc.lpszClassName = kWndClass;
            atom = RegisterClassExW(&wc);
            return atom;
        }
    }

    PromptResult PasswordPromptWindow::Prompt(const std::wstring& title, const std::wstring& message, unsigned timeoutMs)
    {
        PromptResult out{};
        EnsureClass();

        State st{};
        st.title = title;
        st.message = message;
        st.remainingMs = (timeoutMs == 0) ? 30'000 : timeoutMs;

        HWND hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            kWndClass,
            st.title.c_str(),
            WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT, CW_USEDEFAULT, 460, 200,
            nullptr, nullptr, GetModuleHandleW(nullptr), &st);

        if (!hwnd) return out;

        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);

        MSG msg{};
        bool receivedQuit = false;
        int quitCode = 0;
        while (IsWindow(hwnd))
        {
            int gm = GetMessageW(&msg, nullptr, 0, 0);
            if (gm == 0)
            {
                receivedQuit = true;
                quitCode = static_cast<int>(msg.wParam);
                break;
            }
            if (gm < 0)
                break;
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        if (IsWindow(hwnd))
        {
            st.result.approved = false;
            if (!st.result.password.empty())
                SecureZeroMemory(st.result.password.data(), st.result.password.size() * sizeof(wchar_t));
            st.result.password.clear();
            DestroyWindow(hwnd);
        }

        // Preserve a caller's quit request for any outer message loop.
        if (receivedQuit)
            PostQuitMessage(quitCode);

        return st.result;
    }
}


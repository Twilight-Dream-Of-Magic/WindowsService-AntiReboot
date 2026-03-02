#pragma once
#include <windows.h>
#include <string>
#include <fstream>
#include <iterator>
#include <mutex>
#include <sstream>
#include <iomanip>

namespace guard
{
    class SimpleLogger
    {
    public:
        explicit SimpleLogger(std::wstring filePath)
            : filePath_(std::move(filePath)) {}

        void Write(const std::wstring& line)
        {
            std::lock_guard<std::mutex> lock(mu_);
            RotateIfTooLarge_NoThrow();
            std::wofstream ofs(filePath_.c_str(), std::ios::app);
            if (!ofs.is_open()) return;
            ofs << TimeNow() << L" [pid=" << GetCurrentProcessId() << L"] " << line << L"\n";
        }

        const std::wstring& Path() const { return filePath_; }

    private:
        std::wstring filePath_;
        std::mutex mu_;

        void RotateIfTooLarge_NoThrow()
        {
            // Best-effort log rotation to prevent unbounded growth.
            // Keep it simple: when >10MB, rename current log to a timestamped .bak file.
            constexpr ULONGLONG kMaxBytes = 10ULL * 1024ULL * 1024ULL;

            WIN32_FILE_ATTRIBUTE_DATA fad{};
            if (!GetFileAttributesExW(filePath_.c_str(), GetFileExInfoStandard, &fad))
                return;
            if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                return;
            ULONGLONG size = (static_cast<ULONGLONG>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
            if (size < kMaxBytes)
                return;

            SYSTEMTIME st{};
            GetLocalTime(&st);
            wchar_t ts[64] = {};
            swprintf_s(ts, std::size(ts), L"%04u%02u%02u-%02u%02u%02u",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

            std::wstring bak = filePath_ + L"." + ts + L".bak";
            // MOVEFILE_REPLACE_EXISTING in case of rare collisions.
            MoveFileExW(filePath_.c_str(), bak.c_str(), MOVEFILE_REPLACE_EXISTING);
        }

        static std::wstring TimeNow()
        {
            SYSTEMTIME st{};
            GetLocalTime(&st);
            std::wstringstream ss;
            ss << L"["
               << st.wYear << L"-"
               << std::setw(2) << std::setfill(L'0') << st.wMonth << L"-"
               << std::setw(2) << std::setfill(L'0') << st.wDay << L" "
               << std::setw(2) << std::setfill(L'0') << st.wHour << L":"
               << std::setw(2) << std::setfill(L'0') << st.wMinute << L":"
               << std::setw(2) << std::setfill(L'0') << st.wSecond << L"."
               << std::setw(3) << std::setfill(L'0') << st.wMilliseconds
               << L"]";
            return ss.str();
        }
    };
}


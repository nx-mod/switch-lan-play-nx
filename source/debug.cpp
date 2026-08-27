/*
 * Copyright (c) 2018 Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "debug.hpp"

const size_t TlsBackupSize = 0x100;

/* Default ON: there is no companion config app (unlike the original
 * ldn_mitm's ldnmitm_config NRO) that could ever call SetLogging() over
 * IPC, so leaving this false would mean the log file is never created
 * and every LogFormat() call in the codebase is silently a no-op on
 * every real install. Revisit if/when a toggle app exists. */
static std::atomic_bool g_logging_enabled = true;
#define BACKUP_TLS() u8 _tls_backup[TlsBackupSize];memcpy(_tls_backup, armGetTls(), TlsBackupSize);
#define RESTORE_TLS() memcpy(armGetTls(), _tls_backup, TlsBackupSize);

#define MIN(a, b) (((a) > (b)) ? (b) : (a))

ams::Result SetLogging(u32 enabled)
{
    g_logging_enabled = enabled;
    
    if (g_logging_enabled) {
        R_TRY(ams::log::Initialize());
    }
    
    R_SUCCEED();
}

ams::Result GetLogging(u32 *enabled)
{
    *enabled = g_logging_enabled;
    
    R_SUCCEED();
}

namespace ams::log
{
    namespace {
        constexpr const char LogFilePath[] = "sdmc:/switch-lan-play-nx.log";
        fs::FileHandle LogFile;
        s64 LogOffset;

        os::Mutex g_file_log_lock(true);

        // Every LogFormat()/LogHex() call reopens the file fresh (see
        // LogStr()/LogHexImpl()). Recreate-if-missing here, matching
        // Initialize()'s own check: the log file can be deleted out from
        // under a still-running process (e.g. clearing logs over FTP for a
        // fresh test run without a reboot), and OpenFile on a missing file
        // must not be allowed to take the whole sysmodule down.
        Result OpenLogFileForAppend() {
            bool has_file;
            R_TRY(fs::HasFile(&has_file, LogFilePath));
            if (!has_file) {
                R_TRY(fs::CreateFile(LogFilePath, 0));
                LogOffset = 0;
            }
            R_TRY(fs::OpenFile(&LogFile, LogFilePath, fs::OpenMode_Write | fs::OpenMode_AllowAppend));
            R_SUCCEED();
        }
    }

    Result Initialize()
    {
        if (g_logging_enabled) {
            // Check if log file exists and create it if not
            bool has_file;
            R_TRY(fs::HasFile(&has_file, LogFilePath));
            if (!has_file)
            {
                R_TRY(fs::CreateFile(LogFilePath, 0));
            }

            // Get file write offset
            R_TRY(fs::OpenFile(&LogFile, LogFilePath, fs::OpenMode_Write | fs::OpenMode_AllowAppend));
            R_TRY(GetFileSize(&LogOffset, LogFile));

            fs::CloseFile(LogFile);
        }

        R_SUCCEED();
    }

    void Finalize()
    {
        fs::FlushFile(LogFile);
        fs::CloseFile(LogFile);
    }

    // LogPrefix()/LogStr()/LogHexImpl() never use R_ABORT_UNLESS: logging
    // is best-effort diagnostic infrastructure, and a failed log write
    // (e.g. a file-sharing conflict from pulling the log over FTP while
    // this sysmodule is actively writing to it) must never be allowed to
    // take the whole process down mid-game. Skip the line and keep running
    // instead.
    Result LogPrefix()
    {
        char buf[0x100];
        auto thread = os::GetCurrentThread();
        auto ts = os::GetSystemTick().ToTimeSpan();

        auto len = util::TSNPrintf(buf, sizeof(buf), "[ts: %6lums t: (%lu) %-22s p: %d/%d] ",
                                   ts.GetMilliSeconds(),
                                   os::GetThreadId(thread),
                                   os::GetThreadNamePointer(thread),
                                   os::GetThreadPriority(thread) + 28,
                                   os::GetThreadCurrentPriority(thread) + 28);

        R_TRY(fs::WriteFile(LogFile, LogOffset, buf, len, fs::WriteOption::None));
        LogOffset += len;
        R_SUCCEED();
    }

    void LogStr(const char *fmt, std::va_list args)
    {
        if (g_logging_enabled)
        {
            std::scoped_lock lk(g_file_log_lock);
            BACKUP_TLS();
            if (R_SUCCEEDED(OpenLogFileForAppend())) {
                if (R_SUCCEEDED(LogPrefix())) {
                    char buf[0x100];
                    int len = util::TVSNPrintf(buf, sizeof(buf), fmt, args);
                    if (R_SUCCEEDED(fs::WriteFile(LogFile, LogOffset, buf, len, fs::WriteOption::Flush))) {
                        LogOffset += len;
                    }
                }
                fs::CloseFile(LogFile);
            }
            RESTORE_TLS();
        }
    }

    void LogHexImpl(const void *data, int size)
    {
        if (g_logging_enabled)
        {
            u8 *dat = (u8 *)data;
            char buf[0x100];
            LogFormatImpl("Bin Log: %d (%p)\n", size, data);
            BACKUP_TLS();
            if (R_SUCCEEDED(OpenLogFileForAppend())) {
                for (int i = 0; i < size; i += 16)
                {
                    int s = MIN(size - i, 16);
                    buf[0] = 0;
                    for (int j = 0; j < s; j++)
                    {
                        sprintf(buf + strlen(buf), "%02x", dat[i + j]);
                    }
                    sprintf(buf + strlen(buf), "\n");
                    if (!R_SUCCEEDED(fs::WriteFile(LogFile, LogOffset, buf, strlen(buf), fs::WriteOption::Flush))) {
                        break;
                    }
                    LogOffset += strlen(buf);
                }
                fs::CloseFile(LogFile);
            }
            RESTORE_TLS();
        }
    }

    void LogFormatImpl(const char *fmt, ...)
    {
        std::va_list args;
        va_start(args, fmt);
        LogStr(fmt, args);
        va_end(args);
    }
}

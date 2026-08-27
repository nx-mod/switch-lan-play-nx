#include "runtime_cfg.hpp"
#include "servers.h"
#include "../debug.hpp"

#include <cstring>
#include <cstdio>

namespace slpnx::cfg {

    namespace {

        // Config read via ams::fs so we never touch stdio in a boot2 context.
        int ReadConfigText(const char *path, char *buf, size_t cap) {
            ams::fs::FileHandle file;
            ams::Result rc = ams::fs::OpenFile(std::addressof(file), path, ams::fs::OpenMode_Read);
            if (R_FAILED(rc))
                return -1;

            s64 size = 0;
            rc = ams::fs::GetFileSize(std::addressof(size), file);
            if (R_SUCCEEDED(rc) && size > 0 && (u64)size < cap - 1) {
                size_t read = 0;
                rc = ams::fs::ReadFile(std::addressof(read), file, 0, buf, (size_t)size);
                if (R_SUCCEEDED(rc))
                    buf[read] = '\0';
            } else {
                rc = ams::fs::ResultInvalidSize();
            }

            ams::fs::CloseFile(file);
            if (R_FAILED(rc))
                return -1;
            return (int)size;
        }

        bool ReadPersistedSelection(int &out_index) {
            char buf[16];
            int size = ReadConfigText(SELECTED_PATH, buf, sizeof(buf));
            if (size <= 0)
                return false;
            int idx = -1;
            if (std::sscanf(buf, "%d", &idx) != 1)
                return false;
            if (idx < 0)
                return false;
            out_index = idx;
            return true;
        }

        void PersistSelection(int index) {
            char text[16];
            int len = std::snprintf(text, sizeof(text), "%d\n", index);
            if (len <= 0)
                return;

            ams::Result rc = ams::fs::DeleteFile(SELECTED_PATH);
            AMS_UNUSED(rc);
            rc = ams::fs::CreateFile(SELECTED_PATH, len);
            if (R_FAILED(rc)) {
                LogFormat("RuntimeCfg: PersistSelection CreateFile rc=0x%08x", rc.GetValue());
                return;
            }

            ams::fs::FileHandle file;
            rc = ams::fs::OpenFile(std::addressof(file), SELECTED_PATH, ams::fs::OpenMode_Write);
            if (R_SUCCEEDED(rc)) {
                rc = ams::fs::WriteFile(file, 0, text, static_cast<size_t>(len), ams::fs::WriteOption::Flush);
                ams::fs::CloseFile(file);
            }
            if (R_FAILED(rc)) {
                LogFormat("RuntimeCfg: PersistSelection write rc=0x%08x", rc.GetValue());
            }
        }

    }

    RuntimeCfg::RuntimeCfg() : m_sel_index(-1) {}

    int RuntimeCfg::ReloadServers() {
        std::scoped_lock lk(m_mutex);
        char buf[4096];
        int size = ReadConfigText(CONFIG_PATH, buf, sizeof(buf));
        if (size < 0) {
            LogFormat("RuntimeCfg: ReloadServers no %s (using built-in default relay)", CONFIG_PATH);
            return 0;
        }
        int count = slpnxServersParse(buf, (size_t)size);
        LogFormat("RuntimeCfg: ReloadServers loaded %d server(s) from %s", count, CONFIG_PATH);

        int persisted = -1;
        if (ReadPersistedSelection(persisted) && persisted < count) {
            m_sel_index = persisted;
        } else if (m_sel_index < 0 || m_sel_index >= count) {
            m_sel_index = count > 0 ? 0 : -1;
        }
        return count;
    }

    int RuntimeCfg::ServerCount() {
        std::scoped_lock lk(m_mutex);
        return slpnxServersCount();
    }

    const char *RuntimeCfg::ServerName(int index) {
        std::scoped_lock lk(m_mutex);
        const SlpNxServer *s = slpnxServersGet(index);
        return s != nullptr ? s->name : "";
    }

    const char *RuntimeCfg::ServerHost(int index) {
        std::scoped_lock lk(m_mutex);
        const SlpNxServer *s = slpnxServersGet(index);
        return s != nullptr ? s->host : "";
    }

    unsigned short RuntimeCfg::ServerPort(int index) {
        std::scoped_lock lk(m_mutex);
        const SlpNxServer *s = slpnxServersGet(index);
        return s != nullptr ? s->port : 0;
    }

    int RuntimeCfg::SelectServer(u32 index) {
        std::scoped_lock lk(m_mutex);
        if ((int)index >= slpnxServersCount())
            return 0;
        m_sel_index = (int)index;
        PersistSelection(m_sel_index);
        return 1;
    }

    int RuntimeCfg::GetSelectedIndex() {
        std::scoped_lock lk(m_mutex);
        return m_sel_index;
    }

    void RuntimeCfg::GetSelectedHostPort(char *out_host, size_t host_cap, u16 *out_port) {
        std::scoped_lock lk(m_mutex);
        const SlpNxServer *s = slpnxServersGet(m_sel_index);
        if (s != nullptr) {
            std::strncpy(out_host, s->host, host_cap - 1);
            out_host[host_cap - 1] = '\0';
            *out_port = s->port;
        } else {
            std::strncpy(out_host, DefaultRelayHost, host_cap - 1);
            out_host[host_cap - 1] = '\0';
            *out_port = DefaultRelayPort;
        }
    }

    RuntimeCfg &GetRuntimeCfg() {
        static RuntimeCfg cfg;
        return cfg;
    }

}

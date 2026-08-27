#define TESLA_INIT_IMPL // If you have more than one file using the tesla header, only define this in the main one
#include <tesla.hpp>    // The Tesla Header

#include <cstdio>
#include <cstring>
#include <format>
#include <string>

#include "servers.h"
#include "slpnxcfg.h"

/*
 * switch-lan-play-nx overlay 
 */

#define TITLE "switch-lan-play-nx"
#define SERVERS_CONF "sdmc:/config/switch-lan-play-nx/servers.conf"

static SlpNxCfgService g_svc;
static bool g_haveSvc = false;
static char g_version[32] = "?";
static Result g_cfg_error = 0;
static u32 g_connected_val = 0, g_enabled_val = 1, g_sel_val = 0, g_port_val = 0;
static char g_host_val[128] = "";

/* ------------------------------------------------------------------ *
 * Server selection page
 * ------------------------------------------------------------------ */
class ServerGui : public tsl::Gui {
public:
    virtual tsl::elm::Element *createUI() override {
        auto frame = new tsl::elm::OverlayFrame(TITLE, "select relay");
        auto list = new tsl::elm::List();

        const int count = slpnxServersCount();
        if (count == 0) {
            list->addItem(new tsl::elm::ListItem("no servers configured"));
            list->addItem(new tsl::elm::ListItem(SERVERS_CONF));
            frame->setContent(list);
            return frame;
        }

        list->addItem(new tsl::elm::CategoryHeader("Select a relay"));

        for (int i = 0; i < count && i < SLPNXCFG_MAX_SERVERS; i++) {
            const SlpNxServer *srv = slpnxServersGet(i);
            if (srv == nullptr)
                continue;

            auto *item = new tsl::elm::ListItem(srv->name);
            const bool selected = ((u32)i == g_sel_val);
            item->setValue(std::format("{}{}:{}", selected ? "● " : "",
                                       srv->host, srv->port),
                           !selected);

            const int index = i;
            item->setClickListener([index](u64 keys) {
                if (!(keys & HidNpadButton_A))
                    return false;

                if (g_haveSvc) {
                    slpnxCfgSelectServer(&g_svc, (u32)index);
                    /* Drop the current relay socket and reconnect against the
                     * newly selected host/port immediately -- otherwise the
                     * bridge keeps talking to the OLD relay until the game
                     * (or console) is restarted, which defeats the point of
                     * a runtime picker. See BsdBridgeService::ForceReconnect. */
                    slpnxCfgReconnect(&g_svc);
                    g_sel_val = (u32)index;
                }
                tsl::goBack();
                return true;
            });
            list->addItem(item);
        }

        frame->setContent(list);
        return frame;
    }
};

/* ------------------------------------------------------------------ *
 * Main page
 * ------------------------------------------------------------------ */
class MainGui : public tsl::Gui {
public:
    MainGui() {}

    tsl::elm::OverlayFrame *m_frame = nullptr;
    tsl::elm::ListItem *m_realIp = nullptr;     // our real WiFi-assigned IP (nifm)
    tsl::elm::ListItem *m_status = nullptr;
    tsl::elm::ListItem *m_serverIp = nullptr;   // selected relay's own host:port
    tsl::elm::ListItem *m_serverRow = nullptr;
    u32 m_frameCount = 0;

    virtual tsl::elm::Element *createUI() override {
        auto frame = new tsl::elm::OverlayFrame(TITLE, g_version);
        auto list = new tsl::elm::List();
        m_frame = frame;

        if (!g_haveSvc) {
            BuildNotRunningUI(list);
            frame->setContent(list);
            return frame;
        }

        // Standalone "IP" (our real WiFi-assigned address) sits above the
        // "Relay" section, which covers which server is selected (plus ITS
        // address) and whether we're connected to it. Each is its own short
        // row (a combined "Connected  host:port" value used to overflow the
        // row width and render overlapping the label, looked like a button
        // with text bleeding through it).
        m_realIp = new tsl::elm::ListItem("IP");
        list->addItem(m_realIp);

        list->addItem(new tsl::elm::CategoryHeader("Relay"));

        if (slpnxServersCount() == 0) {
            auto *none = new tsl::elm::ListItem("Selected");
            none->setValue("none configured", true);
            list->addItem(none);
            list->addItem(new tsl::elm::ListItem(SERVERS_CONF));
        } else {
            m_serverRow = new tsl::elm::ListItem("Selected");
            m_serverRow->setClickListener([](u64 keys) {
                if (keys & HidNpadButton_A) {
                    tsl::changeTo<ServerGui>();
                    return true;
                }
                return false;
            });
            list->addItem(m_serverRow);
        }

        m_serverIp = new tsl::elm::ListItem("Server IP");
        list->addItem(m_serverIp);

        m_status = new tsl::elm::ListItem("State");
        list->addItem(m_status);

        list->addItem(new tsl::elm::CategoryHeader("Controls"));
        AddAction(list, "Start", [] { slpnxCfgStart(&g_svc); });
        AddAction(list, "Stop", [] { slpnxCfgStop(&g_svc); });
        AddAction(list, "Reconnect", [] { slpnxCfgReconnect(&g_svc); });

        frame->setContent(list);
        this->refresh();
        return frame;
    }

    virtual void update() override {
        /* ~2x/second -- one cheap IPC call, no SD access. */
        if (++m_frameCount % 30 == 0)
            this->refresh();
    }

    virtual bool handleInput(u64, u64, const HidTouchState &,
                             HidAnalogStickState, HidAnalogStickState) override {
        return false;
    }

private:
    template<typename F>
    void AddAction(tsl::elm::List *list, const char *label, F action) {
        auto *item = new tsl::elm::ListItem(label);
        item->setClickListener([this, action](u64 keys) {
            if (keys & HidNpadButton_A) {
                action();
                this->refresh();
                return true;
            }
            return false;
        });
        list->addItem(item);
    }

    void BuildNotRunningUI(tsl::elm::List *list) {
        if (g_cfg_error == SLPNXCFG_RESULT_NOT_INSTALLED) {
            list->addItem(new tsl::elm::CategoryHeader("Sysmodule not running"));
            list->addItem(new tsl::elm::ListItem("switch-lan-play-nx isn't"));
            list->addItem(new tsl::elm::ListItem("installed or hasn't started."));
            list->addItem(new tsl::elm::CategoryHeader("To fix"));
            list->addItem(new tsl::elm::ListItem("1. Install via the top-level"));
            list->addItem(new tsl::elm::ListItem("   Makefile's PACK target"));
            list->addItem(new tsl::elm::ListItem("2. Reboot the console"));
        } else {
            list->addItem(new tsl::elm::CategoryHeader("slpnx:cfg unavailable"));
            list->addItem(new tsl::elm::ListItem(
                std::format("connect failed 0x{:X}", g_cfg_error)));
            list->addItem(new tsl::elm::ListItem("Try rebooting the console."));
        }
    }

    void refresh() {
        if (!g_haveSvc)
            return;

        u32 connected = 0, enabled = 1, sel = 0, port = 0;
        char host[128] = "";
        char local_ip[16] = "";
        char real_ip[16] = "";
        if (R_FAILED(slpnxCfgGetState(&g_svc, &connected, &enabled, &sel, host, &port, local_ip, real_ip))) {
            if (m_status != nullptr)
                m_status->setValue("service lost", true);
            return;
        }
        g_connected_val = connected;
        g_enabled_val = enabled;
        g_sel_val = sel;
        g_port_val = port;
        std::strncpy(g_host_val, host, sizeof(g_host_val) - 1);

        // "IP" (top-level) is our real WiFi-assigned address (nifm), always
        // available once nifm is up regardless of relay/LDN state.
        // "Server IP" (in Relay) is the SELECTED relay's own host:port.
        if (m_realIp != nullptr)
            m_realIp->setValue(real_ip[0] != '\0' ? real_ip : "(unavailable)", real_ip[0] == '\0');
        if (m_status != nullptr) {
            const char *state = connected ? "Connected" : (enabled ? "Offline" : "Stopped");
            m_status->setValue(state, !connected);
        }
        if (m_serverIp != nullptr)
            m_serverIp->setValue(std::format("{}:{}", host, port), false);

        const SlpNxServer *srv = slpnxServersGet((int)sel);
        if (m_serverRow != nullptr)
            m_serverRow->setValue(srv != nullptr ? srv->name : "none", srv == nullptr);

        if (m_frame != nullptr) {
            std::string sub = g_version;
            if (srv != nullptr)
                sub += std::format("  ·  {}", srv->name);
            m_frame->setSubtitle(sub);
        }
    }
};

class SlpNxOverlay : public tsl::Overlay {
public:
    virtual void initServices() override {
        tsl::hlp::doWithSmSession([&] {
            g_cfg_error = slpnxCfgGetConfig(&g_svc);
        });
        g_haveSvc = R_SUCCEEDED(g_cfg_error);
        if (g_haveSvc) {
            slpnxCfgGetVersion(&g_svc, g_version);
            // The sysmodule loads servers.conf once at boot; without this,
            // an entry added/edited on SD after boot is invisible to
            // SelectServer -- it validates the index against ITS OWN stale
            // count and silently rejects anything past the end. Reload here
            // so opening the overlay always re-syncs the sysmodule's list
            // with whatever's currently on the card, no reboot required.
            slpnxCfgReload(&g_svc);
        }

        tsl::hlp::doWithSDCardHandle([&] {
            slpnxServersLoad(SERVERS_CONF);
        });
    }

    virtual void exitServices() override {
        if (g_haveSvc)
            slpnxCfgClose(&g_svc);
    }

    virtual void onShow() override {}
    virtual void onHide() override {}

    virtual std::unique_ptr<tsl::Gui> loadInitialGui() override {
        return initially<MainGui>();
    }
};

int main(int argc, char **argv) {
    return tsl::loop<SlpNxOverlay>(argc, argv);
}

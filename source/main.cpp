/*
 * main.cpp -- switch-lan-play-nx entry point.
 *
 * Adapted from the real ldn_mitm's own ldnmitm_main.cpp (this project's
 * sibling, C:\PROJECTS\switch\test\ldn_mitm\source\ldnmitm_main.cpp) --
 * that file is the PROVEN pattern for a MITM sysmodule's boot/registration
 * sequence on this exact toolchain. The only change: mitm target is
 * "bsd:u" instead of "ldn:u", and the registered service is our
 * BsdBridgeService, which only actually intercepts traffic for ldn_mitm's
 * own process (see bsd_bridge_service.cpp's ShouldMitm) -- every other
 * process's bsd:u session sees this sysmodule as if it doesn't exist,
 * exactly as Atmosphere's mitm framework guarantees for any ShouldMitm
 * that returns false.
 */
#include <stratosphere.hpp>

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <malloc.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <switch.h>

extern "C" {
#include <switch/services/bsd.h>
}

#include "bsd/bsd_bridge_service.hpp"
#include "cfg/runtime_cfg.hpp"
#include "cfg/cfg_service.hpp"

namespace ams {

    namespace {

        constexpr size_t MallocBufferSize = 1_MB;
        alignas(os::MemoryPageSize) constinit u8 g_malloc_buffer[MallocBufferSize];

        // nifmInitialize/bsdInitialize/socketInitialize deliberately do NOT
        // happen here: this module's program id (0x4200000000000009) is
        // below ldn_mitm's (0x4200000000000010) specifically so boot2
        // launches it first, but every millisecond spent before
        // RegisterMitmServer below is a millisecond in which ldn_mitm could
        // grab its own direct bsd:u session and permanently bypass this
        // mitm entirely (ShouldMitm never even gets a chance to fire). The
        // relay socket stack is instead lazy-initialized inside
        // BsdBridgeService::EnsureRelayConnected() on first use.
    }

    // slpnx:cfg -- standalone (non-mitm) IPC service the switch-lan-play-nx
    // Tesla overlay talks to. Runs on its own ServerManager and thread,
    // separate from the mitm ServerManager below.
    namespace cfg {

        const s32 ThreadPriority = 10;
        const size_t ThreadStackSize = 0x4000;
        alignas(os::MemoryPageSize) u8 g_thread_stack[ThreadStackSize];
        os::ThreadType g_thread;

        struct ConfigServerManagerOptions {
            static constexpr size_t PointerBufferSize    = 0x100;
            static constexpr size_t MaxDomains           = 0;
            static constexpr size_t MaxDomainObjects     = 0;
            static constexpr bool   CanDeferInvokeRequest = false;
            static constexpr bool   CanManageMitmServers  = false;
        };

        constexpr size_t MaxSessions = 2;
        using ConfigServerManager = sf::hipc::ServerManager<1, ConfigServerManagerOptions, MaxSessions>;
        ConfigServerManager g_server_manager;

        void LoopConfigServerThread(void *) {
            g_server_manager.LoopProcess();
        }

    }

    namespace mitm {

        const s32 ThreadPriority = 6;
        // ldn_mitm's own bsdInitialize() opens TWO concurrent bsd:u sessions
        // (g_bsdSrv + g_bsdMonitor) from the SAME client pid. Single-threaded
        // dispatch is required here: with multiple worker threads, those two
        // sessions' accept/command processing can land on different threads
        // close together, and ldn_mitm fatals with svc::ResultSessionClosed
        // when it tries to dispatch StartMonitoring on the monitor session
        // right after RegisterClient succeeds on the other one.
        const size_t TotalThreads = 1;
        const size_t NumExtraThreads = TotalThreads - 1;
        const size_t ThreadStackSize = 0x8000;

        alignas(os::MemoryPageSize) u8 g_thread_stack[ThreadStackSize];
        os::ThreadType g_thread;

        // Larger than ldn_mitm's own 128KB: this process also carries the
        // relay reassembly buffers (relay_bridge.hpp).
        alignas(0x40) constinit u8 g_heap_memory[256_KB];
        constinit lmem::HeapHandle g_heap_handle;
        constinit bool g_heap_initialized;
        constinit os::SdkMutex g_heap_init_mutex;

        lmem::HeapHandle GetHeapHandle() {
            if (AMS_UNLIKELY(!g_heap_initialized)) {
                std::scoped_lock lk(g_heap_init_mutex);
                if (AMS_LIKELY(!g_heap_initialized)) {
                    g_heap_handle = lmem::CreateExpHeap(g_heap_memory, sizeof(g_heap_memory), lmem::CreateOption_ThreadSafe);
                    g_heap_initialized = true;
                }
            }
            return g_heap_handle;
        }

        void *Allocate(size_t size) { return lmem::AllocateFromExpHeap(GetHeapHandle(), size); }
        void Deallocate(void *p, size_t size) { AMS_UNUSED(size); return lmem::FreeToExpHeap(GetHeapHandle(), p); }

        namespace {

            struct BsdBridgeManagerOptions {
                static constexpr size_t PointerBufferSize = 0x1000;
                static constexpr size_t MaxDomains = 0x10;
                static constexpr size_t MaxDomainObjects = 0x100;
                static constexpr bool   CanDeferInvokeRequest = false;
                static constexpr bool   CanManageMitmServers  = true;
            };

            // ShouldMitm (bsd_bridge_service.cpp) now accepts every
            // process's bsd:u session, not just ldn_mitm's -- a game's own
            // gameplay socket needs to be visible here too (see that file's
            // own header comment). That means a session per bsd:u client
            // process actually STAYS OPEN for as long as that process is
            // running, not just momentarily during boot's declined-attempt
            // interleaving (the old rationale for 16). A live console can
            // easily have qlaunch/the current game plus several background
            // sysmodules with their own bsd:u sessions concurrently; sized
            // generously rather than risk a real client getting refused.
            constexpr size_t MaxSessions = 48;

            class ServerManager final : public sf::hipc::ServerManager<1, BsdBridgeManagerOptions, MaxSessions> {
                private:
                    virtual ams::Result OnNeedsToAccept(int port_index, Server *server) override;
            };

            ServerManager g_server_manager;

            Result ServerManager::OnNeedsToAccept(int port_index, Server *server) {
                AMS_UNUSED(port_index);
                std::shared_ptr<::Service> fsrv;
                sm::MitmProcessInfo client_info;
                server->AcknowledgeMitmSession(std::addressof(fsrv), std::addressof(client_info));
                LogFormat("switch-lan-play-nx: OnNeedsToAccept pid=%lu program_id=0x%016lx",
                    client_info.process_id.value, client_info.program_id.value);
                Result rc = this->AcceptMitmImpl(server,
                    sf::CreateSharedObjectEmplaced<mitm::bsd::IBsdBridgeService, mitm::bsd::BsdBridgeService>(decltype(fsrv)(fsrv), client_info),
                    fsrv);
                LogFormat("switch-lan-play-nx: OnNeedsToAccept -> rc=0x%x", rc.GetValue());
                return rc;
            }

            alignas(os::MemoryPageSize) u8 g_extra_thread_stacks[NumExtraThreads][ThreadStackSize];
            os::ThreadType g_extra_threads[NumExtraThreads];

            void LoopServerThread(void *) {
                g_server_manager.LoopProcess();
            }

            void ProcessForServerOnAllThreads(void *) {
                if constexpr (NumExtraThreads > 0) {
                    const s32 priority = os::GetThreadCurrentPriority(os::GetCurrentThread());
                    for (size_t i = 0; i < NumExtraThreads; i++) {
                        R_ABORT_UNLESS(os::CreateThread(g_extra_threads + i, LoopServerThread, nullptr, g_extra_thread_stacks[i], ThreadStackSize, priority));
                        os::SetThreadNamePointer(g_extra_threads + i, "switch-lan-play-nx::Thread");
                    }
                }
                if constexpr (NumExtraThreads > 0) {
                    for (size_t i = 0; i < NumExtraThreads; i++) {
                        os::StartThread(g_extra_threads + i);
                    }
                }
                LoopServerThread(nullptr);
                if constexpr (NumExtraThreads > 0) {
                    for (size_t i = 0; i < NumExtraThreads; i++) {
                        os::WaitThread(g_extra_threads + i);
                    }
                }
            }
        }
    }

    namespace init {

        void InitializeSystemModule() {
            R_ABORT_UNLESS(sm::Initialize());

            fs::InitializeForSystem();
            fs::SetAllocator(mitm::Allocate, mitm::Deallocate);
            fs::SetEnabledAutoAbort(false);

            R_ABORT_UNLESS(fs::MountSdCard("sdmc"));

            // nifm/bsd/socket intentionally NOT initialized here: every ms
            // spent before RegisterMitmServer below is a chance for
            // ldn_mitm -- which boot2 launches right after us, program id
            // 0x4200000000000009 < ldn_mitm's 0x4200000000000010 -- to grab
            // its own direct bsd:u session and permanently bypass this mitm
            // entirely. The relay socket stack is lazy-initialized on first
            // use instead, inside BsdBridgeService::EnsureRelayConnected().
        }

        void FinalizeSystemModule() { /* ... */ }

        void Startup() {
            init::InitializeAllocator(g_malloc_buffer, sizeof(g_malloc_buffer));
        }
    }

    void NORETURN Exit(int rc) {
        AMS_UNUSED(rc);
        AMS_ABORT("Exit called by immortal process");
    }

    void Main() {
        R_ABORT_UNLESS(log::Initialize());
        LogFormat("switch-lan-play-nx: main");

        // bsd:u mitm registration comes FIRST and nothing new is inserted
        // ahead of it -- see the boot-race comment above InitializeSystemModule.
        // The real fix for that race is res/mitm.lst's DeclareFutureMitm
        // (sm defers any other process's bsd:u connection, including
        // ldn_mitm's own bsdInitialize(), until RegisterMitmServer is called
        // below, regardless of timing), but keeping this call as early as
        // possible costs nothing and matches this file's existing caution.
        constexpr sm::ServiceName MitmServiceName = sm::ServiceName::Encode("bsd:u");
        R_ABORT_UNLESS((mitm::g_server_manager.RegisterMitmServer<mitm::bsd::BsdBridgeService>(0, MitmServiceName)));
        LogFormat("switch-lan-play-nx: registered as bsd:u mitm");

        R_ABORT_UNLESS(os::CreateThread(
            &mitm::g_thread, mitm::ProcessForServerOnAllThreads, nullptr,
            mitm::g_thread_stack, mitm::ThreadStackSize, mitm::ThreadPriority));
        os::SetThreadNamePointer(&mitm::g_thread, "switch-lan-play-nx::MainThread");
        os::StartThread(&mitm::g_thread);

        // Load sdmc:/config/switch-lan-play-nx/servers.conf (cfg/runtime_cfg.hpp)
        // and bring up slpnx:cfg -- the overlay's IPC service -- only after
        // the mitm registration above has already won its race.
        slpnx::cfg::GetRuntimeCfg().ReloadServers();

        /* slpnx:cfg standalone service */
        constexpr sm::ServiceName ConfigServiceName = sm::ServiceName::Encode("slpnx:cfg");
        auto config_service = sf::CreateSharedObjectEmplaced<slpnx::ipc::IConfigService, slpnx::ipc::ConfigService>();
        R_ABORT_UNLESS(cfg::g_server_manager.RegisterObjectForServer(
            std::move(config_service), ConfigServiceName, cfg::MaxSessions));

        R_ABORT_UNLESS(os::CreateThread(&cfg::g_thread, cfg::LoopConfigServerThread, nullptr,
            cfg::g_thread_stack, cfg::ThreadStackSize, cfg::ThreadPriority));
        os::SetThreadNamePointer(&cfg::g_thread, "switch-lan-play-nx::CfgThread");
        os::StartThread(&cfg::g_thread);
        LogFormat("switch-lan-play-nx: registered as slpnx:cfg");

        os::WaitThread(&mitm::g_thread);
    }
}

void *operator new(size_t size) { return ams::mitm::Allocate(size); }
void *operator new(size_t size, const std::nothrow_t &) { return ams::mitm::Allocate(size); }
void operator delete(void *p) { return ams::mitm::Deallocate(p, 0); }
void operator delete(void *p, size_t size) { return ams::mitm::Deallocate(p, size); }
void *operator new[](size_t size) { return ams::mitm::Allocate(size); }
void *operator new[](size_t size, const std::nothrow_t &) { return ams::mitm::Allocate(size); }
void operator delete[](void *p) { return ams::mitm::Deallocate(p, 0); }
void operator delete[](void *p, size_t size) { return ams::mitm::Deallocate(p, size); }

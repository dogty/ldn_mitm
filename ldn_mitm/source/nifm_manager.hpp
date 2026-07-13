#pragma once
#include <stratosphere.hpp>

namespace ams::mitm::ldn {

    /* nifm:a only allows two sessions system-wide. Holding one for the whole
       life of the sysmodule (as ldn_mitm historically did) starves other
       components — most visibly the console's Internet Settings / connection
       test. Acquire the session lazily and refcounted instead, so it is only
       held while ldn is actually in use.
       Ported from DefenderOfHyrule/ldn_mitm. */
    class NifmSessionManager {
        private:
            static os::SdkMutex g_mutex;
            static bool g_initialized;
            static int g_refcount;
        public:
            static Result Acquire();
            static void Release();
    };

    /* RAII acquire/release for short-lived nifm use (e.g. a single IPC). */
    class ScopedNifmSession {
        private:
            Result rc;
        public:
            ScopedNifmSession() : rc(NifmSessionManager::Acquire()) { /* ... */ }
            ~ScopedNifmSession() {
                if (R_SUCCEEDED(rc)) {
                    NifmSessionManager::Release();
                }
            }
            Result GetResult() const { return rc; }
    };

}

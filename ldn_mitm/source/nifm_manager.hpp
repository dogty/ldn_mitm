#pragma once
#include <stratosphere.hpp>

namespace ams::mitm::ldn {

    /* nifm:a allows only two sessions system-wide; holding one for the whole
       sysmodule life starves other components (e.g. the connection test).
       Acquire lazily and refcounted instead. */
    class NifmSessionManager {
        private:
            static os::SdkMutex g_mutex;
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
            ScopedNifmSession() : rc(NifmSessionManager::Acquire()) {}
            ~ScopedNifmSession() {
                if (R_SUCCEEDED(rc)) {
                    NifmSessionManager::Release();
                }
            }
            Result GetResult() const { return rc; }
    };

}

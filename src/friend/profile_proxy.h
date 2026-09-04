/**
 * Profile-server proxy.
 *
 * polcore connects to the profile server directly from inside the game process
 * (sockaddr at polcore+0x404AB8). If that connection drops -- server restart,
 * crash, anything -- FFXi enters its connection-error state and the player is
 * dropped to "POL-0008 Connection terminated or not available". Verified by
 * tracing the error screen to a vtable method at FFXi+0x23BCE0 that posts
 * category-8 DAT messages the moment the socket dies.
 *
 * The proxy takes over the ports polcore dials and forwards to the real server
 * behind them, so the socket the game holds never drops. When the upstream is
 * down the client socket is held open and silent while the proxy reconnects
 * with exponential backoff; traffic resumes when it returns.
 */
#ifndef __XILOADER_PROFILE_PROXY_H_INCLUDED__
#define __XILOADER_PROFILE_PROXY_H_INCLUDED__

#include <cstdint>

namespace xiloader
{
    namespace profile_proxy
    {
        /**
         * Start proxy listeners.
         *
         * Binds each port in listenPorts on 127.0.0.1 and forwards to
         * upstreamIp on (port + upstreamPortOffset). Returns false if any
         * listener could not be bound -- in that case nothing is started and
         * the caller should fall back to a direct connection.
         */
        /**
         * Start the proxy on the first FREE port at or above each base, and
         * report which ones were taken.
         *
         * Ports must be per-client: several clients run on one machine, and
         * they cannot share a listener. An earlier version bound fixed ports
         * with SO_REUSEADDR, which on Windows lets a second process bind the
         * same address -- the second client's polcore then talked through the
         * FIRST client's proxy and inherited its account. Binds are exclusive
         * now and each client claims its own pair.
         *
         * greetLine (optional) is sent on every upstream PUSH connection, so
         * the server can tell whose channel it is; the push channel carries no
         * identity of its own.
         */
        bool start(const char* upstreamIp,
                   uint16_t profileBase, uint16_t upstreamProfilePort,
                   uint16_t pushBase,    uint16_t upstreamPushPort,
                   uint16_t* outProfilePort, uint16_t* outPushPort,
                   const char* greetLine = nullptr);

        /* Stop listeners and drop live sessions. Safe to call if not started. */
        void stop();
    }
}

#endif

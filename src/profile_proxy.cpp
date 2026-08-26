#include "profile_proxy.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <thread>
#include <vector>
#include <mutex>
#include <cstring>

#include "console.h"

namespace xiloader
{
    namespace profile_proxy
    {
        namespace
        {
            std::atomic<bool>   g_running{false};
            std::vector<SOCKET> g_listeners;
            std::mutex          g_listenersMtx;
            char                g_upstreamIp[64] = {};
            uint16_t            g_greetPort      = 0;
            char                g_greetLine[128] = {};

            /* Reconnect backoff. Starts responsive so an ordinary server
             * restart is invisible, then backs off so a server that is gone
             * for good does not spin. */
            constexpr DWORD  kBackoffStartMs = 250;
            constexpr DWORD  kBackoffMaxMs   = 5000;
            constexpr size_t kMaxPending     = 1u << 20;

            SOCKET connect_upstream(uint16_t port)
            {
                SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s == INVALID_SOCKET)
                    return INVALID_SOCKET;

                sockaddr_in addr = {};
                addr.sin_family = AF_INET;
                addr.sin_port   = htons(port);
                inet_pton(AF_INET, g_upstreamIp, &addr.sin_addr);

                if (connect(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
                {
                    closesocket(s);
                    return INVALID_SOCKET;
                }
                return s;
            }

            /* Relay one client session.
             *
             * The client socket is NEVER closed because the upstream died --
             * that is the entire point of this proxy. While upstream is down
             * the client sees a quiet connection, and anything it sends is
             * buffered and flushed on reconnect. The session ends only when
             * the CLIENT hangs up. */
            void session(SOCKET client, uint16_t upstreamPort)
            {
                SOCKET up      = INVALID_SOCKET;
                DWORD  backoff = kBackoffStartMs;
                DWORD  nextTry = 0;
                bool   warned  = false;

                std::vector<char> pending;
                char buf[8192];

                while (g_running.load())
                {
                    if (up == INVALID_SOCKET)
                    {
                        const DWORD now = GetTickCount();
                        if (now < nextTry)
                        {
                            Sleep(20);
                        }
                        else
                        {
                            up = connect_upstream(upstreamPort);
                            if (up == INVALID_SOCKET)
                            {
                                if (!warned)
                                {
                                    xiloader::console::output_to_channel("friend",
                                        "ProfileProxy: upstream :%u down, holding client socket and retrying",
                                        upstreamPort);
                                    warned = true;
                                }
                                nextTry = now + backoff;
                                backoff = (backoff * 2 > kBackoffMaxMs) ? kBackoffMaxMs : backoff * 2;
                            }
                            else
                            {
                                if (warned)
                                {
                                    xiloader::console::output_to_channel("friend",
                                        "ProfileProxy: upstream :%u reconnected", upstreamPort);
                                    warned = false;
                                }
                                backoff = kBackoffStartMs;
                                /* Re-sent on every reconnect: the server binds
                                 * per upstream connection, not per session. */
                                if (g_greetPort != 0 && upstreamPort == g_greetPort &&
                                    g_greetLine[0] != 0)
                                {
                                    send(up, g_greetLine, (int)strlen(g_greetLine), 0);
                                }
                                if (!pending.empty())
                                {
                                    send(up, pending.data(), (int)pending.size(), 0);
                                    pending.clear();
                                }
                            }
                        }
                    }

                    fd_set rd;
                    FD_ZERO(&rd);
                    FD_SET(client, &rd);
                    if (up != INVALID_SOCKET)
                        FD_SET(up, &rd);

                    timeval tv;
                    tv.tv_sec  = 0;
                    tv.tv_usec = 200 * 1000;

                    const int ready = select(0, &rd, nullptr, nullptr, &tv);
                    if (ready == SOCKET_ERROR)
                        break;
                    if (ready == 0)
                        continue;

                    if (FD_ISSET(client, &rd))
                    {
                        const int n = recv(client, buf, sizeof(buf), 0);
                        if (n <= 0)
                            break;
                        if (up != INVALID_SOCKET)
                        {
                            if (send(up, buf, n, 0) == SOCKET_ERROR)
                            {
                                closesocket(up);
                                up = INVALID_SOCKET;
                                if (pending.size() + n <= kMaxPending)
                                    pending.insert(pending.end(), buf, buf + n);
                            }
                        }
                        else if (pending.size() + n <= kMaxPending)
                        {
                            pending.insert(pending.end(), buf, buf + n);
                        }
                    }

                    if (up != INVALID_SOCKET && FD_ISSET(up, &rd))
                    {
                        const int n = recv(up, buf, sizeof(buf), 0);
                        if (n <= 0)
                        {
                            closesocket(up);
                            up      = INVALID_SOCKET;
                            nextTry = GetTickCount() + backoff;
                        }
                        else if (send(client, buf, n, 0) == SOCKET_ERROR)
                        {
                            break;
                        }
                    }
                }

                if (up != INVALID_SOCKET)
                    closesocket(up);
                closesocket(client);
            }

            void listener(SOCKET srv, uint16_t upstreamPort)
            {
                while (g_running.load())
                {
                    sockaddr_in from    = {};
                    int         fromLen = sizeof(from);

                    SOCKET c = accept(srv, (sockaddr*)&from, &fromLen);
                    if (c == INVALID_SOCKET)
                    {
                        if (!g_running.load())
                            break;
                        Sleep(50);
                        continue;
                    }
                    std::thread(session, c, upstreamPort).detach();
                }
                closesocket(srv);
            }
        }

        namespace
        {
            /* Bind the first free port at or above base. Exclusive, so a
             * second client fails over to the next port instead of silently
             * sharing the first client's listener. */
            SOCKET bind_free(uint16_t base, uint16_t tries, uint16_t* chosen)
            {
                for (uint16_t i = 0; i < tries; i++)
                {
                    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (srv == INVALID_SOCKET)
                        return INVALID_SOCKET;

                    BOOL exclusive = TRUE;
                    setsockopt(srv, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                               (const char*)&exclusive, sizeof(exclusive));

                    sockaddr_in addr = {};
                    addr.sin_family      = AF_INET;
                    addr.sin_port        = htons((uint16_t)(base + i));
                    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

                    if (bind(srv, (sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR &&
                        listen(srv, 8) != SOCKET_ERROR)
                    {
                        *chosen = (uint16_t)(base + i);
                        return srv;
                    }
                    closesocket(srv);
                }
                return INVALID_SOCKET;
            }
        }

        bool start(const char* upstreamIp,
                   uint16_t profileBase, uint16_t upstreamProfilePort,
                   uint16_t pushBase,    uint16_t upstreamPushPort,
                   uint16_t* outProfilePort, uint16_t* outPushPort,
                   const char* greetLine)
        {
            if (g_running.load())
                return true;

            strncpy_s(g_upstreamIp, upstreamIp, _TRUNCATE);
            g_greetPort = upstreamPushPort;
            if (greetLine != nullptr)
                strncpy_s(g_greetLine, greetLine, _TRUNCATE);
            else
                g_greetLine[0] = 0;

            uint16_t pPort = 0, qPort = 0;
            SOCKET   profileSrv = bind_free(profileBase, 8, &pPort);
            if (profileSrv == INVALID_SOCKET)
            {
                xiloader::console::output(xiloader::color::warning,
                    "ProfileProxy: no free port near %u", profileBase);
                return false;
            }
            SOCKET   pushSrv    = bind_free(pushBase, 8, &qPort);
            if (pushSrv == INVALID_SOCKET)
            {
                closesocket(profileSrv);
                xiloader::console::output(xiloader::color::warning,
                    "ProfileProxy: no free port near %u", pushBase);
                return false;
            }

            g_running.store(true);
            {
                std::lock_guard<std::mutex> lk(g_listenersMtx);
                g_listeners.clear();
                g_listeners.push_back(profileSrv);
                g_listeners.push_back(pushSrv);
            }

            std::thread(listener, profileSrv, upstreamProfilePort).detach();
            std::thread(listener, pushSrv,    upstreamPushPort).detach();

            if (outProfilePort) *outProfilePort = pPort;
            if (outPushPort)    *outPushPort    = qPort;

            xiloader::console::output_to_channel("friend",
                "ProfileProxy: 127.0.0.1:%u -> %s:%u (profile), 127.0.0.1:%u -> %s:%u (push)",
                pPort, g_upstreamIp, upstreamProfilePort,
                qPort, g_upstreamIp, upstreamPushPort);
            return true;
        }

        void stop()
        {
            if (!g_running.exchange(false))
                return;

            std::lock_guard<std::mutex> lk(g_listenersMtx);
            for (size_t i = 0; i < g_listeners.size(); i++)
                closesocket(g_listeners[i]);
            g_listeners.clear();
        }
    }
}

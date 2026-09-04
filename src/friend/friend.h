/*
 * friend.h -- Friend system public API.
 *
 * Everything the friend list needs lives under src/friend/. The rest of
 * xiloader calls the functions below at fixed seams; every one of them is a
 * no-op unless enable(true) was called, so with the toggle off the upstream
 * code paths run unchanged.
 */

#pragma once

#include <cstdint>
#include <winsock2.h>

struct IPOLCoreCom;

namespace friend_system {
    void        enable(bool on);
    bool        enabled();

    void        set_account_id(uint32_t accid);       // command_handler.h, on login success
    uint32_t    account_id();

    bool        is_profile_host(const char* name);   // Mine_gethostbyname: ppNNN.pol.com
    const char* launch_args();                       // appended to the polcore /game command line

    void attach();                                   // main(): after the upstream detours are committed
    void bootstrap(IPOLCoreCom* polcore);            // main(): after SetProfileServerPort
    void shutdown();                                 // main(): before the upstream detours are detached

    void on_send(SOCKET s, const char* buf, int len); // Mine_send
    void on_lobby_key();                             // network.cpp: FFXiDataComm key exchange
    void on_ffxi_data_done(int packets);             // network.cpp: after the FFXi data loop

    void init();
    void on_tick();
    void activate();
}

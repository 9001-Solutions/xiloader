/*
 * friend.h — Friend system public API.
 */

#pragma once

#include <cstdint>
#include <string>
#include <winsock2.h>

struct IPOLCoreCom;

namespace friend_system {
    /* Core lifecycle */
    void init();                                        // called from activate()
    void on_tick();                                     // called at ~60Hz from worker thread
    void shutdown();                                    // called on exit
    void bootstrap(IPOLCoreCom* polcore);               // post-polcore setup (auth, config, CreateFriendList)
    void activate();                                    // called from PolDataComm after lobby login
    void on_send(SOCKET s, const char* buf, int len);   // called from Mine_send for profile protocol
    bool is_active();                                   // true after activate() completes

    /* Befriend operations (Phase 1-3) */
    void request_befriend(const std::string& charname, const std::string& nickname);
    void request_accept(uint32_t from_accid, const std::string& nickname);
    void request_decline(uint32_t from_accid);
    void request_remove(uint32_t target_accid);

    /* Friend messaging (Phase 4) */
    void send_message(uint32_t to_accid, const std::string& subject, const std::string& body);

    /* Force a CallerB refresh (used after befriend operations) */
    void force_refresh();
}

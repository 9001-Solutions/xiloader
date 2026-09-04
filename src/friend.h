/*
 * friend.h -- Friend system public API.
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
}

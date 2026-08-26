/*
===========================================================================

Copyright (c) 2010-2014 Darkstar Dev Teams

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/

This file is part of DarkStar-server source code.

===========================================================================
*/

#pragma once

#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <map>
#include <memory>
#include <mutex>

namespace xiloader
{
    /**
    * @brief Console color enumeration.
    */
    enum class color
    {
        /* Red color codes. */
        red = FOREGROUND_RED,
        lightred = FOREGROUND_RED | FOREGROUND_INTENSITY,

        /* Green color codes. */
        green = FOREGROUND_GREEN,
        lightgreen = FOREGROUND_GREEN | FOREGROUND_INTENSITY,

        /* Blue color codes. */
        blue = FOREGROUND_BLUE,
        lightblue = FOREGROUND_BLUE | FOREGROUND_INTENSITY,

        /* Cyan color codes. */
        cyan = FOREGROUND_BLUE | FOREGROUND_GREEN,
        lightcyan = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY,

        /* Yellow color codes. */
        yellow = FOREGROUND_GREEN | FOREGROUND_RED,
        lightyelllow = FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY,

        /* Purple color codes. */
        purple = FOREGROUND_BLUE | FOREGROUND_RED,
        lightpurple = FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY,

        /* White color codes. */
        grey = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
        white = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,

        /* Common color codes. */
        debug = lightcyan,
        error = lightred,
        info = white,
        success = lightgreen,
        warning = lightyelllow
    };

    /**
     * @brief Console class containing helper functions for console output.
     */
    class console
    {
    private:

        /**
         * @brief Shows or hides the console based on the provided argument.
         *
         * @param visible   "true" to show the console, "false" to hide it.
         */
        static void visible(bool visible);

        /**
         * @brief Append a line to the persistent log file. Thread-safe.
         * Written to xiloader.log in the working directory.
         * Opened lazily on first write, flushed on every line so the file is
         * always up-to-date and readable externally even mid-session.
         */
        static void log_to_file(std::string const& line)
        {
            static std::mutex s_log_mtx;
            static std::ofstream s_log;
            std::lock_guard<std::mutex> lk(s_log_mtx);
            if (!s_log.is_open())
            {
                s_log.open("xiloader.log",
                           std::ios::out | std::ios::app);
            }
            if (s_log.is_open())
            {
                s_log << line << std::endl;
                s_log.flush();
            }
        }

        /**
         * @brief Append a line to a per-channel persistent log file.
         * `channel` becomes part of the filename: `xiloader-{channel}.log`.
         * For high-frequency diagnostic streams (per-frame UI hooks etc.)
         * that would drown out the main log. Each channel keeps its own
         * lazy-opened ofstream + mutex; the path is per-channel cached on
         * first call.
         */
        static void log_to_named_file(char const* channel, std::string const& line)
        {
            struct Channel { std::mutex mtx; std::ofstream stream; };
            static std::mutex s_map_mtx;
            static std::map<std::string, std::unique_ptr<Channel>> s_channels;

            Channel* ch = nullptr;
            {
                std::lock_guard<std::mutex> lk(s_map_mtx);
                auto& slot = s_channels[channel];
                if (!slot)
                {
                    slot = std::make_unique<Channel>();
                    std::string path = std::string("xiloader-")
                                     + channel + ".log";
                    slot->stream.open(path, std::ios::out | std::ios::app);
                }
                ch = slot.get();
            }

            std::lock_guard<std::mutex> lk(ch->mtx);
            if (ch->stream.is_open())
            {
                ch->stream << line << std::endl;
                ch->stream.flush();
            }
        }

    public:

        /**
         * @brief Prints a text fragment with the specified color to the console.
         *
         * @param c         The color to print the fragment with.
         * @param message   The fragment to print.
         */
        static void print(xiloader::color c, std::string const& message);

        /**
         * @brief Prints the given message to the console.
         *
         * @param format    The format of the message to print.
         * @param args      The arguments to fill the format.
         */
        template<typename... Args>
        static void output(char const* format, Args... args)
        {
            output(xiloader::color::white, format, args...);
        }

        static std::string getTimestamp()
        {
            /* Get the current timestamp */
            ::__time32_t rawtime;
            ::_time32(&rawtime);

            ::tm timeinfo;
            ::_localtime32_s(&timeinfo, &rawtime);

            /* Format the timestamp */
            char timestamp[256];
            ::strftime(timestamp, sizeof timestamp, "[%m/%d/%y %H:%M:%S] ", &timeinfo);

            return timestamp;
        }
        /**
         * @brief Prints the given message to the console with the specific color.
         *
         * @param c         The color to print the message with.
         * @param format    The format of the message to print.
         * @param args      The arguments to fill the format.
         */
        template<typename... Args>
        static void output(xiloader::color c, char const* format, Args... args)
        {
            std::string timestamp = getTimestamp();

            /* Output the timestamp */
            print(xiloader::color::lightyelllow, timestamp.c_str());

            /* Parse the incoming message */
            char buffer[1024];
            ::snprintf(buffer, sizeof buffer, format, args...);
            /* Output the message */

            print(c, buffer);

            std::cout << std::endl;

            /* Also append to persistent log file for external inspection */
            log_to_file(timestamp + buffer);
        }

        /**
         * @brief High-frequency diagnostic sink. Writes ONLY to
         * `xiloader-{channel}.log`, with NO console print and NO main-log
         * write. Use for hooks that fire many times per frame (per-row UI
         * dispatch, per-tick state probes) where the volume would drown
         * out the main log but the data is still worth keeping for
         * post-hoc inspection.
         */
        template<typename... Args>
        static void output_to_channel(char const* channel, char const* format, Args... args)
        {
            std::string timestamp = getTimestamp();
            char buffer[1024];
            ::snprintf(buffer, sizeof buffer, format, args...);
            log_to_named_file(channel, timestamp + buffer);
        }

        static void printMultiLine(std::string msg, const std::string delimiter, const xiloader::color color)
        {
            auto pos = msg.find(delimiter);

            while (pos != -1)
            {
                xiloader::console::output(color, "%s", msg.substr(0, pos).c_str());
                msg.erase(0, pos + delimiter.length());

                pos = msg.find(delimiter);
            }

            xiloader::console::output(color, "%s", msg.c_str());
        }

        /**
         * @brief Hides the console window.
         */
        static void hide();

        /**
         * @brief Shows the console window.
         */
        static void show();
    };

}; // namespace xiloader

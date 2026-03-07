#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <optional>
#include <cstdint>

namespace LiquidHookEx {
    namespace HookConfig {

        constexpr const char* CONFIG_PATH = "hooks.json";

        // Must stay in sync with LiquidHookEx::RipSlotTarget
        enum class RipSlotTarget : uint8_t {
            HookData = 0,
            OriginalFunc = 1,
            Custom = 2,
        };

        struct RipSlotEntry {
            uintptr_t     remoteAddr = 0;   // address of the remote indirection slot
            RipSlotTarget target = RipSlotTarget::HookData;
            uint64_t      customAddr = 0;   // only meaningful when target == Custom
        };

        struct HookEntry {
            uint32_t                  pid = 0;
            std::string               hookName;
            uintptr_t                 dataRemote = 0;
            uintptr_t                 shellcodeRemote = 0;
            uintptr_t                 targetFunction = 0;
            uintptr_t                 callSiteAddr = 0;
            uintptr_t                 origStorage = 0;
            std::vector<RipSlotEntry> ripSlots;

            // CallSite: original instruction bytes saved for exact restore.
            // Empty for LiquidHookEx (vtable) hooks.
            std::vector<uint8_t>      origBytes;
        };

        // -----------------------------------------------------------------------
        // Internal helpers
        // -----------------------------------------------------------------------
        namespace detail {

            inline std::string uintToHex(uintptr_t v) {
                char buf[32];
                snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
                return buf;
            }

            inline uintptr_t hexToUint(const std::string& s) {
                if (s.empty()) return 0;
                return (uintptr_t)strtoull(s.c_str(), nullptr, 16);
            }

            inline std::string bytesToHex(const std::vector<uint8_t>& bytes) {
                std::string s;
                s.reserve(bytes.size() * 2);
                static const char* hex = "0123456789ABCDEF";
                for (uint8_t b : bytes) {
                    s += hex[b >> 4];
                    s += hex[b & 0xF];
                }
                return s;
            }

            inline std::vector<uint8_t> hexToBytes(const std::string& s) {
                std::vector<uint8_t> result;
                for (size_t i = 0; i + 1 < s.size(); i += 2) {
                    auto nibble = [](char c) -> uint8_t {
                        if (c >= '0' && c <= '9') return c - '0';
                        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                        return 0;
                        };
                    result.push_back((nibble(s[i]) << 4) | nibble(s[i + 1]));
                }
                return result;
            }

            inline size_t findValueStart(const std::string& json, const std::string& key) {
                const std::string token = "\"" + key + "\":";
                size_t pos = 0;
                while (pos < json.size()) {
                    auto hit = json.find(token, pos);
                    if (hit == std::string::npos) return std::string::npos;

                    if (hit > 0) {
                        char before = json[hit - 1];
                        if (before != ' ' && before != '\t' && before != '\n' &&
                            before != '\r' && before != '{' && before != ',') {
                            pos = hit + 1;
                            continue;
                        }
                    }
                    return hit + token.size();
                }
                return std::string::npos;
            }

            inline std::string extractString(const std::string& json, const std::string& key) {
                size_t after_colon = findValueStart(json, key);
                if (after_colon == std::string::npos) return {};
                auto q1 = json.find('"', after_colon);
                if (q1 == std::string::npos) return {};
                auto q2 = json.find('"', q1 + 1);
                if (q2 == std::string::npos) return {};
                return json.substr(q1 + 1, q2 - q1 - 1);
            }

            inline uint32_t extractUint(const std::string& json, const std::string& key) {
                size_t i = findValueStart(json, key);
                if (i == std::string::npos) return 0;
                while (i < json.size() &&
                    (json[i] == ' ' || json[i] == '\t' ||
                        json[i] == '\n' || json[i] == '\r'))
                    ++i;
                return (uint32_t)strtoul(json.c_str() + i, nullptr, 10);
            }

            // Parses:
            // "ripSlots": [
            //   { "addr": "0x...", "target": 0 },
            //   { "addr": "0x...", "target": 2, "customAddr": "0x..." },
            //   ...
            // ]
            inline std::vector<RipSlotEntry> extractRipSlots(const std::string& json) {
                std::vector<RipSlotEntry> result;

                size_t after_colon = findValueStart(json, "ripSlots");
                if (after_colon == std::string::npos) return result;

                auto arrStart = json.find('[', after_colon);
                auto arrEnd = json.find(']', after_colon);
                if (arrStart == std::string::npos || arrEnd == std::string::npos) return result;

                // Walk each { ... } object inside the array
                size_t pos = arrStart + 1;
                while (pos < arrEnd) {
                    auto objStart = json.find('{', pos);
                    if (objStart == std::string::npos || objStart >= arrEnd) break;
                    auto objEnd = json.find('}', objStart);
                    if (objEnd == std::string::npos || objEnd > arrEnd) break;

                    std::string obj = json.substr(objStart, objEnd - objStart + 1);

                    RipSlotEntry e;
                    e.remoteAddr = hexToUint(extractString(obj, "addr"));
                    e.target = static_cast<RipSlotTarget>(extractUint(obj, "target"));
                    e.customAddr = hexToUint(extractString(obj, "customAddr"));

                    result.push_back(e);
                    pos = objEnd + 1;
                }
                return result;
            }

            inline HookEntry parseEntry(const std::string& block) {
                HookEntry e;
                e.pid = extractUint(block, "pid");
                e.hookName = extractString(block, "hookName");
                e.dataRemote = hexToUint(extractString(block, "dataRemote"));
                e.shellcodeRemote = hexToUint(extractString(block, "shellcodeRemote"));
                e.targetFunction = hexToUint(extractString(block, "targetFunction"));
                e.callSiteAddr = hexToUint(extractString(block, "callSiteAddr"));
                e.origStorage = hexToUint(extractString(block, "origStorage"));
                e.ripSlots = extractRipSlots(block);
                std::string origBytesHex = extractString(block, "origBytes");
                if (!origBytesHex.empty())
                    e.origBytes = hexToBytes(origBytesHex);
                return e;
            }

            inline std::string serializeEntry(const HookEntry& e) {
                std::string s = std::string("  {\n")
                    + "    \"pid\": " + std::to_string(e.pid) + ",\n"
                    + "    \"hookName\": \"" + e.hookName + "\",\n"
                    + "    \"dataRemote\": \"" + uintToHex(e.dataRemote) + "\",\n"
                    + "    \"shellcodeRemote\": \"" + uintToHex(e.shellcodeRemote) + "\",\n"
                    + "    \"targetFunction\": \"" + uintToHex(e.targetFunction) + "\"";

                if (e.callSiteAddr)
                    s += ",\n    \"callSiteAddr\": \"" + uintToHex(e.callSiteAddr) + "\"";

                if (e.origStorage)
                    s += ",\n    \"origStorage\": \"" + uintToHex(e.origStorage) + "\"";

                if (!e.origBytes.empty())
                    s += ",\n    \"origBytes\": \"" + bytesToHex(e.origBytes) + "\"";

                if (!e.ripSlots.empty()) {
                    s += ",\n    \"ripSlots\": [\n";
                    for (size_t i = 0; i < e.ripSlots.size(); ++i) {
                        const auto& slot = e.ripSlots[i];
                        s += "      { \"addr\": \"" + uintToHex(slot.remoteAddr) + "\""
                            + ", \"target\": " + std::to_string(static_cast<int>(slot.target));
                        if (slot.target == RipSlotTarget::Custom)
                            s += ", \"customAddr\": \"" + uintToHex(slot.customAddr) + "\"";
                        s += " }";
                        if (i + 1 < e.ripSlots.size()) s += ",";
                        s += "\n";
                    }
                    s += "    ]";
                }

                s += "\n  }";
                return s;
            }

        } // namespace detail

        inline std::vector<HookEntry> Load() {
            std::vector<HookEntry> entries;
            std::ifstream f(CONFIG_PATH);
            if (!f.is_open()) return entries;

            std::string json((std::istreambuf_iterator<char>(f)),
                std::istreambuf_iterator<char>());

            // Track brace depth so nested { } inside ripSlots don't confuse the parser
            size_t pos = 0;
            while (pos < json.size()) {
                auto start = json.find('{', pos);
                if (start == std::string::npos) break;

                int    depth = 0;
                size_t end = start;
                for (size_t j = start; j < json.size(); ++j) {
                    if (json[j] == '{') ++depth;
                    else if (json[j] == '}') { --depth; if (depth == 0) { end = j; break; } }
                }

                std::string block = json.substr(start, end - start + 1);
                HookEntry e = detail::parseEntry(block);
                if (!e.hookName.empty())
                    entries.push_back(e);
                pos = end + 1;
            }
            return entries;
        }

        inline bool Save(const std::vector<HookEntry>& entries) {
            std::ofstream f(CONFIG_PATH, std::ios::trunc);
            if (!f.is_open()) return false;

            f << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) {
                f << detail::serializeEntry(entries[i]);
                if (i + 1 < entries.size()) f << ',';
                f << '\n';
            }
            f << "]\n";
            return f.good();
        }

        inline std::optional<HookEntry> Find(const std::string& hookName, uint32_t pid = 0) {
            for (auto& e : Load()) {
                if (e.hookName == hookName && (pid == 0 || e.pid == pid))
                    return e;
            }
            return std::nullopt;
        }

        inline bool Upsert(const HookEntry& entry) {
            auto entries = Load();
            for (auto& e : entries) {
                if (e.hookName == entry.hookName) {
                    e = entry;
                    return Save(entries);
                }
            }
            entries.push_back(entry);
            return Save(entries);
        }

        inline bool Remove(const std::string& hookName) {
            auto entries = Load();
            auto before = entries.size();
            entries.erase(
                std::remove_if(entries.begin(), entries.end(),
                    [&](const HookEntry& e) { return e.hookName == hookName; }),
                entries.end());
            if (entries.size() == before) return true;
            return Save(entries);
        }

    } // namespace HookConfig


}
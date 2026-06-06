/*
// Copyright (c) 2026 American Megatrends International LLC (AMI)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "sel_redfish_map.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifndef SEL_REDFISH_MAP_PATH
#define SEL_REDFISH_MAP_PATH "/usr/share/intel-ipmi-oem/sel_redfish_map.json"
#endif

namespace intel_oem::ipmi::sel
{

namespace
{

using json = nlohmann::json;

// IPMI bytes addressable by name from JSON.
struct EvalCtx
{
    uint8_t eventData1;
    uint8_t eventData2;
    uint8_t eventData3;
    uint8_t sensorNum;
    uint8_t offset;
    std::string sensorName;
    std::string rawHex;
};

// Compiled representation of one arg in an entry.
struct ArgSpec
{
    enum class Source
    {
        literal,
        sensorName,
        rawHex,
        byte,
        channelLetter,
        mappedString,
    };
    Source source = Source::literal;

    // For literal.
    std::string literal;

    // For byte/channelLetter/mappedString.
    enum class From
    {
        eventData1,
        eventData2,
        eventData3,
        sensorNum,
        offset,
    };
    From from = From::eventData2;
    uint8_t mask = 0xFF;
    uint8_t shift = 0;
    int add = 0;
    std::string format = "%d"; // for byte
    char base = 'A';           // for channelLetter

    // For mappedString.
    std::unordered_map<uint8_t, std::string> cases;
    std::string defaultCase;
};

// Compiled representation of one mapping entry.
struct Entry
{
    std::string messageId;
    std::vector<ArgSpec> args;
    // assert specifier: nullopt = match either; true = assert only; false =
    // deassert only.
    std::optional<bool> assertSpec;
};

// Lookup key (sensorType in [0,255] for specific rows, 0x100 for wildcard).
struct Key
{
    uint16_t sensorType; // 0..0xFF or 0x100 wildcard
    uint8_t eventType;
    uint8_t offset;
    bool operator==(const Key& other) const noexcept
    {
        return sensorType == other.sensorType && eventType == other.eventType &&
               offset == other.offset;
    }
};
struct KeyHash
{
    size_t operator()(const Key& key) const noexcept
    {
        return (static_cast<size_t>(key.sensorType) << 16) |
               (static_cast<size_t>(key.eventType) << 8) |
               static_cast<size_t>(key.offset);
    }
};

constexpr uint16_t WILDCARD_SENSOR_TYPE = 0x100;

// ----- helpers -----

static long parseIntFlexible(const std::string& text, long defaultVal = 0)
{
    if (text.empty())
    {
        return defaultVal;
    }
    try
    {
        size_t pos = 0;
        if (text.size() > 2 && text[0] == '0' &&
            (text[1] == 'x' || text[1] == 'X'))
        {
            return std::stol(text.substr(2), &pos, 16);
        }
        return std::stol(text, &pos, 0);
    }
    catch (...)
    {
        return defaultVal;
    }
}

static long jsonIntFlexible(const json& node, long defaultVal = 0)
{
    if (node.is_number_integer())
    {
        return node.get<long>();
    }
    if (node.is_string())
    {
        return parseIntFlexible(node.get<std::string>(), defaultVal);
    }

    return defaultVal;
}

static uint8_t evalFromByte(ArgSpec::From from, const EvalCtx& ctx)
{
    switch (from)
    {
        case ArgSpec::From::eventData1:
        {
            return ctx.eventData1;
        }
        case ArgSpec::From::eventData2:
        {
            return ctx.eventData2;
        }
        case ArgSpec::From::eventData3:
        {
            return ctx.eventData3;
        }
        case ArgSpec::From::sensorNum:
        {
            return ctx.sensorNum;
        }
        case ArgSpec::From::offset:
        {
            return ctx.offset;
        }
    }
    return 0;
}

static ArgSpec::From parseFrom(const std::string& name,
                               ArgSpec::From defaultFrom)
{
    if (name == "eventData1")
    {
        return ArgSpec::From::eventData1;
    }
    if (name == "eventData2")
    {
        return ArgSpec::From::eventData2;
    }
    if (name == "eventData3")
    {
        return ArgSpec::From::eventData3;
    }
    if (name == "sensorNum")
    {
        return ArgSpec::From::sensorNum;
    }
    if (name == "offset")
    {
        return ArgSpec::From::offset;
    }
    return defaultFrom;
}

static std::string renderArg(const ArgSpec& spec, const EvalCtx& ctx)
{
    switch (spec.source)
    {
        case ArgSpec::Source::literal:
        {
            return spec.literal;
        }

        case ArgSpec::Source::sensorName:
        {
            return ctx.sensorName;
        }

        case ArgSpec::Source::rawHex:
        {
            return ctx.rawHex;
        }

        case ArgSpec::Source::byte:
        {
            uint8_t byteValue = evalFromByte(spec.from, ctx);
            byteValue =
                static_cast<uint8_t>((byteValue >> spec.shift) & spec.mask);
            int adjustedValue = static_cast<int>(byteValue) + spec.add;
            char buf[32];
            std::snprintf(buf, sizeof(buf), spec.format.c_str(), adjustedValue);
            return buf;
        }

        case ArgSpec::Source::channelLetter:
        {
            uint8_t byteValue = evalFromByte(spec.from, ctx);
            byteValue =
                static_cast<uint8_t>((byteValue >> spec.shift) & spec.mask);
            char buf[2] = {static_cast<char>(spec.base + byteValue), 0};
            return buf;
        }

        case ArgSpec::Source::mappedString:
        {
            uint8_t byteValue = evalFromByte(spec.from, ctx);
            byteValue =
                static_cast<uint8_t>((byteValue >> spec.shift) & spec.mask);
            auto it = spec.cases.find(byteValue);
            if (it != spec.cases.end())
            {
                return it->second;
            }
            if (!spec.defaultCase.empty())
            {
                return spec.defaultCase;
            }
            char buf[8];
            std::snprintf(buf, sizeof(buf), "%d", byteValue);
            return buf;
        }
    }
    return {};
}

static bool parseArg(const json& node, ArgSpec& out)
{
    if (!node.is_object() || !node.contains("source") ||
        !node["source"].is_string())
    {
        return false;
    }
    std::string sourceName = node["source"].get<std::string>();

    if (sourceName == "literal")
    {
        out.source = ArgSpec::Source::literal;
        out.literal = node.value("value", std::string{});
        return true;
    }
    if (sourceName == "sensorName")
    {
        out.source = ArgSpec::Source::sensorName;
        return true;
    }
    if (sourceName == "rawHex")
    {
        out.source = ArgSpec::Source::rawHex;
        return true;
    }
    if (sourceName == "byte" || sourceName == "channelLetter" ||
        sourceName == "mappedString")
    {
        if (sourceName == "byte")
        {
            out.source = ArgSpec::Source::byte;
        }
        else if (sourceName == "channelLetter")
        {
            out.source = ArgSpec::Source::channelLetter;
        }
        else
        {
            out.source = ArgSpec::Source::mappedString;
        }

        out.from = parseFrom(node.value("from", std::string{"eventData2"}),
                             ArgSpec::From::eventData2);
        out.mask = static_cast<uint8_t>(
            jsonIntFlexible(node.value("mask", json("0xFF")), 0xFF) & 0xFF);
        out.shift = static_cast<uint8_t>(
            jsonIntFlexible(node.value("shift", json(0)), 0) & 0x07);
        out.add =
            static_cast<int>(jsonIntFlexible(node.value("add", json(0)), 0));
        if (node.contains("format") && node["format"].is_string())
        {
            out.format = node["format"].get<std::string>();
        }
        if (node.contains("base") && node["base"].is_string() &&
            !node["base"].get<std::string>().empty())
        {
            out.base = node["base"].get<std::string>()[0];
        }

        if (out.source == ArgSpec::Source::mappedString &&
            node.contains("cases"))
        {
            const auto& cases = node["cases"];
            if (cases.is_object())
            {
                for (auto it = cases.begin(); it != cases.end(); ++it)
                {
                    uint8_t caseKey = static_cast<uint8_t>(
                        parseIntFlexible(it.key(), 0) & 0xFF);
                    if (it.value().is_string())
                    {
                        out.cases[caseKey] = it.value().get<std::string>();
                    }
                }
            }
            if (node.contains("default") && node["default"].is_string())
            {
                out.defaultCase = node["default"].get<std::string>();
            }
        }
        return true;
    }
    return false;
}

} // namespace

struct SelRedfishMap::Impl
{
    std::string registryPrefix = "AMI.1.0.";
    // MessageIds already published under the upstream OpenBMC.0.1.* registry
    // keep their original prefix so bmcweb can still resolve them into a
    // human-readable Message. New MessageIds added under AMI use
    // registryPrefix above.
    std::string openbmcRegistryPrefix = "OpenBMC.0.1.";
    std::unordered_set<std::string> openbmcMessageIds;
    std::unordered_map<Key, std::vector<Entry>, KeyHash> table;

    // Threshold offset -> generic Id (used only if no entry matches).
    std::unordered_map<uint8_t, std::string> thresholdByOffset;
    std::string discreteAssertId;
    std::string discreteDeassertId;
    std::string lastResortId;

    bool loaded = false;

    void loadFromFile(const std::string& path);
    const Entry* lookup(uint8_t sensorType, uint8_t eventType, uint8_t offset,
                        bool assert) const;
};

void SelRedfishMap::Impl::loadFromFile(const std::string& path)
{
    std::ifstream inputStream(path);
    if (!inputStream.is_open())
    {
        // No file -> module is a no-op; callers fall back to legacy behavior.
        return;
    }

    json doc;
    try
    {
        inputStream >> doc;
    }
    catch (const std::exception& parseError)
    {
        std::cerr << "[sel_redfish_map] parse error in " << path << ": "
                  << parseError.what() << "\n";
        return;
    }

    if (doc.contains("registry_prefix") && doc["registry_prefix"].is_string())
    {
        registryPrefix = doc["registry_prefix"].get<std::string>();
    }

    if (doc.contains("openbmc_registry_prefix") &&
        doc["openbmc_registry_prefix"].is_string())
    {
        openbmcRegistryPrefix =
            doc["openbmc_registry_prefix"].get<std::string>();
    }

    if (doc.contains("openbmc_message_ids") &&
        doc["openbmc_message_ids"].is_array())
    {
        for (const auto& messageIdNode : doc["openbmc_message_ids"])
        {
            if (messageIdNode.is_string())
            {
                openbmcMessageIds.insert(messageIdNode.get<std::string>());
            }
        }
    }

    if (doc.contains("entries") && doc["entries"].is_array())
    {
        for (const auto& entryNode : doc["entries"])
        {
            // Allow string "comments" interleaved in the array - skip them.
            if (!entryNode.is_object())
            {
                continue;
            }
            if (!entryNode.contains("messageId") ||
                !entryNode["messageId"].is_string())
            {
                continue;
            }
            if (!entryNode.contains("eventType"))
            {
                continue;
            }
            if (!entryNode.contains("offset"))
            {
                continue;
            }

            uint16_t parsedSensorType = WILDCARD_SENSOR_TYPE;
            if (entryNode.contains("sensorType"))
            {
                if (entryNode["sensorType"].is_string() &&
                    entryNode["sensorType"].get<std::string>() == "*")
                {
                    parsedSensorType = WILDCARD_SENSOR_TYPE;
                }
                else
                {
                    long sensorTypeValue =
                        jsonIntFlexible(entryNode["sensorType"], -1);
                    if (sensorTypeValue < 0 || sensorTypeValue > 0xFF)
                    {
                        continue;
                    }
                    parsedSensorType = static_cast<uint16_t>(sensorTypeValue);
                }
            }

            long eventTypeValue = jsonIntFlexible(entryNode["eventType"], -1);
            long offsetValue = jsonIntFlexible(entryNode["offset"], -1);
            if (eventTypeValue < 0 || eventTypeValue > 0xFF ||
                offsetValue < 0 || offsetValue > 0xFF)
            {
                continue;
            }

            Entry entry;
            entry.messageId = entryNode["messageId"].get<std::string>();
            if (entryNode.contains("assert") &&
                entryNode["assert"].is_boolean())
            {
                entry.assertSpec = entryNode["assert"].get<bool>();
            }

            if (entryNode.contains("args") && entryNode["args"].is_array())
            {
                for (const auto& argNode : entryNode["args"])
                {
                    ArgSpec argSpec;
                    if (parseArg(argNode, argSpec))
                    {
                        entry.args.push_back(std::move(argSpec));
                    }
                }
            }

            Key key{parsedSensorType, static_cast<uint8_t>(eventTypeValue),
                    static_cast<uint8_t>(offsetValue)};
            table[key].push_back(std::move(entry));
        }
    }

    if (doc.contains("fallbacks") && doc["fallbacks"].is_object())
    {
        const auto& fallbacks = doc["fallbacks"];
        if (fallbacks.contains("thresholdByOffset") &&
            fallbacks["thresholdByOffset"].is_object())
        {
            for (auto it = fallbacks["thresholdByOffset"].begin();
                 it != fallbacks["thresholdByOffset"].end(); ++it)
            {
                uint8_t offsetKey =
                    static_cast<uint8_t>(parseIntFlexible(it.key(), 0) & 0xFF);
                if (it.value().is_string())
                {
                    thresholdByOffset[offsetKey] =
                        it.value().get<std::string>();
                }
            }
        }
        if (fallbacks.contains("discreteAssert") &&
            fallbacks["discreteAssert"].is_string())
        {
            discreteAssertId = fallbacks["discreteAssert"].get<std::string>();
        }
        if (fallbacks.contains("discreteDeassert") &&
            fallbacks["discreteDeassert"].is_string())
        {
            discreteDeassertId =
                fallbacks["discreteDeassert"].get<std::string>();
        }
        if (fallbacks.contains("lastResort") &&
            fallbacks["lastResort"].is_string())
        {
            lastResortId = fallbacks["lastResort"].get<std::string>();
        }
    }

    loaded = true;
}

const Entry* SelRedfishMap::Impl::lookup(uint8_t sensorType, uint8_t eventType,
                                         uint8_t offset, bool assert) const
{
    auto matchBySensorType = [&](uint16_t lookupSensorType) -> const Entry* {
        Key key{lookupSensorType, eventType, offset};
        auto it = table.find(key);
        if (it == table.end())
        {
            return nullptr;
        }
        const Entry* unspecifiedMatch = nullptr;
        for (const auto& entry : it->second)
        {
            if (!entry.assertSpec.has_value())
            {
                if (!unspecifiedMatch)
                {
                    unspecifiedMatch = &entry;
                }
                continue;
            }
            if (*entry.assertSpec == assert)
            {
                return &entry;
            }
        }
        return unspecifiedMatch;
    };

    if (auto specificMatch = matchBySensorType(sensorType))
    {
        return specificMatch;
    }
    return matchBySensorType(WILDCARD_SENSOR_TYPE);
}

// ---------- public API ----------

SelRedfishMap& SelRedfishMap::instance()
{
    static SelRedfishMap inst;
    return inst;
}

SelRedfishMap::SelRedfishMap() : impl(new Impl())
{
    impl->loadFromFile(SEL_REDFISH_MAP_PATH);
}

SelRedfishMap::~SelRedfishMap()
{
    delete impl;
}

std::pair<std::string, std::string> SelRedfishMap::splitIdArgs(
    const std::string& message)
{
    auto commaPos = message.find(',');
    if (commaPos == std::string::npos)
    {
        return {message, std::string{}};
    }
    return {message.substr(0, commaPos), message.substr(commaPos + 1)};
}

std::string SelRedfishMap::format(
    uint16_t /*generatorID*/, uint8_t sensorType, uint8_t sensorNum,
    uint8_t eventType, uint8_t eventData1, uint8_t eventData2,
    uint8_t eventData3, const std::string& sensorPath) const
{
    if (!impl->loaded)
    {
        return {};
    }

    EvalCtx ctx;
    ctx.eventData1 = eventData1;
    ctx.eventData2 = eventData2;
    ctx.eventData3 = eventData3;
    ctx.sensorNum = sensorNum;
    ctx.offset = static_cast<uint8_t>(eventData1 & 0x0F);
    // Reuse the standard leaf-name extraction; same convention as
    // sdrutils.hpp (fs::path(path).filename()).
    ctx.sensorName = std::filesystem::path(sensorPath).filename().string();
    // If the sensor cannot be resolved via D-Bus / SDR, present a stable
    // placeholder so message templates always have a readable name.
    // Mirror MegaRAC SP-X convention: OEM sensor-number range (0xC0-0xFF)
    // renders as "OEM (Unknown)"; everything else as "Unknown".
    if (ctx.sensorName.empty())
    {
        ctx.sensorName = (sensorNum >= 0xC0) ? "OEM (Unknown)" : "Unknown";
    }

    {
        char rawHexBuf[32];
        std::snprintf(rawHexBuf, sizeof(rawHexBuf), "%02X%02X%02X%02X%02X%02X",
                      sensorType, sensorNum, eventType, eventData1, eventData2,
                      eventData3);
        ctx.rawHex = rawHexBuf;
    }

    // assert = bit 7 of eventType clear (per IPMI spec event direction).
    bool assert = (eventType & 0x80) == 0;
    uint8_t maskedEventType = eventType & 0x7F;

    std::string messageId;
    const std::vector<ArgSpec>* args = nullptr;

    if (auto entry =
            impl->lookup(sensorType, maskedEventType, ctx.offset, assert))
    {
        messageId = entry->messageId;
        args = &entry->args;
    }
    else if (maskedEventType == 0x01)
    {
        // Threshold without a specific row: use generic threshold fallback.
        auto it = impl->thresholdByOffset.find(ctx.offset);
        if (it != impl->thresholdByOffset.end())
        {
            messageId = it->second;
        }
    }

    if (messageId.empty())
    {
        // Discrete fallback: StateSensorWarning / StateSensorNormal.
        if (assert && !impl->discreteAssertId.empty())
        {
            messageId = impl->discreteAssertId;
        }
        else if (!assert && !impl->discreteDeassertId.empty())
        {
            messageId = impl->discreteDeassertId;
        }
    }

    if (messageId.empty())
    {
        // Last resort.
        if (impl->lastResortId.empty())
        {
            return {};
        }
        messageId = impl->lastResortId;
    }

    const std::string& prefix = impl->openbmcMessageIds.count(messageId)
                                    ? impl->openbmcRegistryPrefix
                                    : impl->registryPrefix;
    std::string out = prefix + messageId;

    if (args && !args->empty())
    {
        for (const auto& argSpec : *args)
        {
            out += ',';
            out += renderArg(argSpec, ctx);
        }
    }
    else if (messageId == impl->lastResortId ||
             messageId == impl->discreteAssertId ||
             messageId == impl->discreteDeassertId ||
             messageId.rfind("SensorThreshold", 0) == 0 ||
             messageId.rfind("StateSensor", 0) == 0)
    {
        // Fallback Ids without a mapped row: synthesize useful args.
        // Dispatch on the chosen messageId (not evType) because a threshold
        // event with an unmapped offset can land on StateSensor* fallback.
        if (messageId == impl->lastResortId)
        {
            out += ',';
            out += ctx.rawHex;
        }
        else if (messageId.rfind("SensorThreshold", 0) == 0)
        {
            // Registry template: "%1 sensor crossed a ... threshold ...
            // Reading=%2 Threshold=%3."  (3 args)
            char readingThresholdBuf[16];
            out += ',';
            out += ctx.sensorName;
            std::snprintf(readingThresholdBuf, sizeof(readingThresholdBuf),
                          ",%d,%d", eventData2, eventData3);
            out += readingThresholdBuf;
        }
        else
        {
            // StateSensorWarning / StateSensorCritical / StateSensorNormal
            // Registry template:
            //   "%1 of %2 state sensor changed from %3 to %4."  (4 args)
            // %1 category, %2 sensor name, %3 previous state, %4 new state.
            char offsetSuffix[24];
            std::snprintf(offsetSuffix, sizeof(offsetSuffix), "offset 0x%02X",
                          ctx.offset);
            const char* previousState = assert ? "Deasserted" : "Asserted";
            const char* newState = assert ? "Asserted" : "Deasserted";
            out += ',';
            out += "Sensor";
            out += ',';
            out += ctx.sensorName;
            out += ',';
            out += previousState;
            out += ' ';
            out += offsetSuffix;
            out += ',';
            out += newState;
        }
    }

    return out;
}

} // namespace intel_oem::ipmi::sel

/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "commandutils.hpp"
#include "types.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/bimap.hpp>
#include <boost/container/flat_map.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus/match.hpp>

#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#pragma once

struct CmpStrVersion
{
    bool operator()(std::string a, std::string b) const
    {
        return strverscmp(a.c_str(), b.c_str()) < 0;
    }
};

using SensorSubTree = boost::container::flat_map<
    std::string,
    boost::container::flat_map<std::string, std::vector<std::string>>,
    CmpStrVersion>;

using SensorNumMap = boost::bimap<int, std::string>;

static constexpr uint16_t maxSensorsPerLUN = 255;
static constexpr uint16_t maxIPMISensors = (maxSensorsPerLUN * 3);
static constexpr uint16_t lun1Sensor0 = 0x100;
static constexpr uint16_t lun3Sensor0 = 0x300;
static constexpr uint16_t invalidSensorNumber = 0xFFFF;
static constexpr uint8_t reservedSensorNumber = 0xFF;

static constexpr uint8_t sysEntityInstance = 0x01;
static constexpr uint8_t eidReserved = 0x00;
static constexpr uint8_t processorSensorType = 0x07;
static constexpr uint8_t sensorSpecificEvent = 0x6f;
static constexpr uint8_t watchdog2SensorType = 0x23;
static constexpr uint8_t osCriticalStop = 0x20;

namespace details
{

// Enable/disable the logging of stats instrumentation
static constexpr bool enableInstrumentation = false;

class IPMIStatsEntry
{
  private:
    int numReadings = 0;
    int numMissings = 0;
    int numStreakRead = 0;
    int numStreakMiss = 0;
    double minValue = 0.0;
    double maxValue = 0.0;
    std::string sensorName;

  public:
    const std::string& getName(void) const
    {
        return sensorName;
    }

    void updateName(std::string_view name)
    {
        sensorName = name;
    }

    // Returns true if this is the first successful reading
    // This is so the caller can log the coefficients used
    bool updateReading(double reading, int raw)
    {
        if constexpr (!enableInstrumentation)
        {
            return false;
        }

        bool first = ((numReadings == 0) && (numMissings == 0));

        // Sensors can use "nan" to indicate unavailable reading
        if (!(std::isfinite(reading)))
        {
            // Only show this if beginning a new streak
            if (numStreakMiss == 0)
            {
                std::cerr << "IPMI sensor " << sensorName
                          << ": Missing reading, byte=" << raw
                          << ", Reading counts good=" << numReadings
                          << " miss=" << numMissings
                          << ", Prior good streak=" << numStreakRead << "\n";
            }

            numStreakRead = 0;
            ++numMissings;
            ++numStreakMiss;

            return first;
        }

        // Only show this if beginning a new streak and not the first time
        if ((numStreakRead == 0) && (numReadings != 0))
        {
            std::cerr << "IPMI sensor " << sensorName
                      << ": Recovered reading, value=" << reading << " byte="
                      << raw << ", Reading counts good=" << numReadings
                      << " miss=" << numMissings
                      << ", Prior miss streak=" << numStreakMiss << "\n";
        }

        // Initialize min/max if the first successful reading
        if (numReadings == 0)
        {
            std::cerr << "IPMI sensor " << sensorName
                      << ": First reading, value=" << reading << " byte=" << raw
                      << "\n";

            minValue = reading;
            maxValue = reading;
        }

        numStreakMiss = 0;
        ++numReadings;
        ++numStreakRead;

        // Only provide subsequent output if new min/max established
        if (reading < minValue)
        {
            std::cerr << "IPMI sensor " << sensorName
                      << ": Lowest reading, value=" << reading
                      << " byte=" << raw << "\n";

            minValue = reading;
        }

        if (reading > maxValue)
        {
            std::cerr << "IPMI sensor " << sensorName
                      << ": Highest reading, value=" << reading
                      << " byte=" << raw << "\n";

            maxValue = reading;
        }

        return first;
    }
};

class IPMIStatsTable
{
  private:
    std::vector<IPMIStatsEntry> entries;

  private:
    void padEntries(size_t index)
    {
        char hexbuf[16];

        // Pad vector until entries[index] becomes a valid index
        while (entries.size() <= index)
        {
            // As name not known yet, use human-readable hex as name
            IPMIStatsEntry newEntry;
            sprintf(hexbuf, "0x%02zX", entries.size());
            newEntry.updateName(hexbuf);

            entries.push_back(std::move(newEntry));
        }
    }

  public:
    void wipeTable(void)
    {
        entries.clear();
    }

    const std::string& getName(size_t index)
    {
        padEntries(index);
        return entries[index].getName();
    }

    void updateName(size_t index, std::string_view name)
    {
        padEntries(index);
        entries[index].updateName(name);
    }

    bool updateReading(size_t index, double reading, int raw)
    {
        padEntries(index);
        return entries[index].updateReading(reading, raw);
    }
};

// This object is global singleton, used from a variety of places
inline IPMIStatsTable sdrStatsTable;
inline static void filterSensors(SensorSubTree& subtree)
{
    subtree.erase(
        std::remove_if(subtree.begin(), subtree.end(),
                       [](SensorSubTree::value_type& kv) {
                           auto& [_, serviceToIfaces] = kv;

                           static std::array<const char*, 1> serviceFilter = {
                               "xyz.openbmc_project.Pmt"};

                           for (const char* service : serviceFilter)
                           {
                               serviceToIfaces.erase(service);
                           }

                           return serviceToIfaces.empty();
                       }),
        subtree.end());
}
inline static uint16_t getSensorSubtree(std::shared_ptr<SensorSubTree>& subtree)
{
    static std::shared_ptr<SensorSubTree> sensorTreePtr;
    static uint16_t sensorUpdatedIndex = 0;
    sd_bus* bus = NULL;
    int ret = sd_bus_default_system(&bus);
    if (ret < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to connect to system bus",
            phosphor::logging::entry("ERRNO=0x%X", -ret));
        sd_bus_unref(bus);
        return sensorUpdatedIndex;
    }
    sdbusplus::bus_t dbus(bus);
    static sdbusplus::bus::match_t sensorAdded(
        dbus,
        "type='signal',member='InterfacesAdded',arg0path='/xyz/openbmc_project/"
        "sensors/'",
        [](sdbusplus::message_t&) { sensorTreePtr.reset(); });

    static sdbusplus::bus::match_t sensorRemoved(
        dbus,
        "type='signal',member='InterfacesRemoved',arg0path='/xyz/"
        "openbmc_project/sensors/'",
        [](sdbusplus::message_t&) { sensorTreePtr.reset(); });

    if (sensorTreePtr)
    {
        subtree = sensorTreePtr;
        return sensorUpdatedIndex;
    }

    sensorTreePtr = std::make_shared<SensorSubTree>();

    auto mapperCall =
        dbus.new_method_call("xyz.openbmc_project.ObjectMapper",
                             "/xyz/openbmc_project/object_mapper",
                             "xyz.openbmc_project.ObjectMapper", "GetSubTree");
    static constexpr const auto depth = 2;
    static constexpr std::array<const char*, 5> interfaces = {
        "xyz.openbmc_project.Sensor.Value", "xyz.openbmc_project.Sensor.State",
        "xyz.openbmc_project.Sensor.Threshold.Warning",
        "xyz.openbmc_project.Sensor.Threshold.Critical",
        "xyz.openbmc_project.Sensor.Threshold.NonRecoverable"};
    mapperCall.append("/xyz/openbmc_project/sensors", depth, interfaces);

    try
    {
        auto mapperReply = dbus.call(mapperCall);
        mapperReply.read(*sensorTreePtr);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return sensorUpdatedIndex;
    }
    filterSensors(*sensorTreePtr);
    subtree = sensorTreePtr;
    sensorUpdatedIndex++;
    // The SDR is being regenerated, wipe the old stats
    sdrStatsTable.wipeTable();
    return sensorUpdatedIndex;
}

inline static bool getSensorNumMap(std::shared_ptr<SensorNumMap>& sensorNumMap)
{
    static std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    bool sensorNumMapUpated = false;
    static uint16_t prevSensorUpdatedIndex = 0;
    std::shared_ptr<SensorSubTree> sensorTree;
    uint16_t curSensorUpdatedIndex = details::getSensorSubtree(sensorTree);
    if (!sensorTree)
    {
        return sensorNumMapUpated;
    }

    if ((curSensorUpdatedIndex == prevSensorUpdatedIndex) && sensorNumMapPtr)
    {
        sensorNumMap = sensorNumMapPtr;
        return sensorNumMapUpated;
    }
    prevSensorUpdatedIndex = curSensorUpdatedIndex;

    sensorNumMapPtr = std::make_shared<SensorNumMap>();

    uint16_t sensorNum = 0;
    uint16_t sensorIndex = 0;
    for (const auto& sensor : *sensorTree)
    {
        sensorNumMapPtr->insert(
            SensorNumMap::value_type(sensorNum, sensor.first));
        sensorIndex++;
        if (sensorIndex == maxSensorsPerLUN)
        {
            sensorIndex = lun1Sensor0;
        }
        else if (sensorIndex == (lun1Sensor0 | maxSensorsPerLUN))
        {
            // Skip assigning LUN 0x2 any sensors
            sensorIndex = lun3Sensor0;
        }
        else if (sensorIndex == (lun3Sensor0 | maxSensorsPerLUN))
        {
            // this is an error, too many IPMI sensors
            throw std::out_of_range("Maximum number of IPMI sensors exceeded.");
        }
        sensorNum = sensorIndex;
    }
    sensorNumMap = sensorNumMapPtr;
    sensorNumMapUpated = true;
    return sensorNumMapUpated;
}
} // namespace details

inline static bool getSensorSubtree(SensorSubTree& subtree)
{
    std::shared_ptr<SensorSubTree> sensorTree;
    details::getSensorSubtree(sensorTree);
    if (!sensorTree)
    {
        return false;
    }

    subtree = *sensorTree;
    return true;
}

struct CmpStr
{
    bool operator()(const char* a, const char* b) const
    {
        return std::strcmp(a, b) < 0;
    }
};

enum class SensorTypeCodes : uint8_t
{
    reserved = 0x0,
    temperature = 0x1,
    voltage = 0x2,
    current = 0x3,
    fan = 0x4,
    processor = 0x07,
    powersupply = 0x08,
    powerunit = 0x09,
    os = 0x20,
    acpisystem = 0x22,
    watchdog2 = 0x23,
    managementsubsystemhealth = 0x28,
    battery = 0x29,
    other = 0xB,
};

enum class SensorEventTypeCodes : uint8_t
{
    unspecified = 0x00,
    threshold = 0x01,
    digitalState = 0x03,
    digitalFailure = 0x04,
    digitalLimit = 0x05,
    digitalPerformance = 0x06,
    digitalPresence = 0x08,
    digitalEnabled = 0x09,
    acpiDevice = 0x0c,
    sensorSpecified = 0x6f
};
// Adding FRU Map
static ipmi::FruMap fruMap;
const static boost::container::flat_map<
    const char*, std::pair<SensorTypeCodes, SensorEventTypeCodes>, CmpStr>
    sensorTypes{
        {{"temperature", std::make_pair(SensorTypeCodes::temperature,
                                        SensorEventTypeCodes::threshold)},
         {"voltage", std::make_pair(SensorTypeCodes::voltage,
                                    SensorEventTypeCodes::threshold)},
         {"current", std::make_pair(SensorTypeCodes::current,
                                    SensorEventTypeCodes::threshold)},
         {"fan_tach", std::make_pair(SensorTypeCodes::fan,
                                     SensorEventTypeCodes::threshold)},
         {"fan_pwm", std::make_pair(SensorTypeCodes::fan,
                                    SensorEventTypeCodes::threshold)},
         {"cpu", std::make_pair(SensorTypeCodes::processor,
                                SensorEventTypeCodes::sensorSpecified)},
         {"powersupply", std::make_pair(SensorTypeCodes::powersupply,
                                        SensorEventTypeCodes::sensorSpecified)},
         {"powerunit", std::make_pair(SensorTypeCodes::powerunit,
                                      SensorEventTypeCodes::sensorSpecified)},
         {"os", std::make_pair(SensorTypeCodes::os,
                               SensorEventTypeCodes::sensorSpecified)},
         {"acpisystem", std::make_pair(SensorTypeCodes::acpisystem,
                                       SensorEventTypeCodes::sensorSpecified)},
         {"watchdog", std::make_pair(SensorTypeCodes::watchdog2,
                                     SensorEventTypeCodes::sensorSpecified)},
         {"battery", std::make_pair(SensorTypeCodes::battery,
                                    SensorEventTypeCodes::sensorSpecified)},
         {"power", std::make_pair(SensorTypeCodes::other,
                                  SensorEventTypeCodes::threshold)},
         {"chassisstate", std::make_pair(SensorTypeCodes::powerunit,
                                         SensorEventTypeCodes::digitalState)},
         {"bmcfirmwarehealth",
          std::make_pair(SensorTypeCodes::managementsubsystemhealth,
                         SensorEventTypeCodes::sensorSpecified)},
         {"acpidevice", std::make_pair(SensorTypeCodes::powersupply,
                                       SensorEventTypeCodes::acpiDevice)}}};

inline static std::string getSensorTypeStringFromPath(const std::string& path)
{
    // get sensor type string from path, path is defined as
    // /xyz/openbmc_project/sensors/<type>/label
    size_t typeEnd = path.rfind("/");
    if (typeEnd == std::string::npos)
    {
        return path;
    }
    size_t typeStart = path.rfind("/", typeEnd - 1);
    if (typeStart == std::string::npos)
    {
        return path;
    }
    // Start at the character after the '/'
    typeStart++;
    return path.substr(typeStart, typeEnd - typeStart);
}

inline static uint8_t getSensorTypeFromPath(const std::string& path)
{
    uint8_t sensorType = 0;
    std::string type = getSensorTypeStringFromPath(path);
    auto findSensor = sensorTypes.find(type.c_str());
    if (findSensor != sensorTypes.end())
    {
        sensorType =
            static_cast<uint8_t>(std::get<SensorTypeCodes>(findSensor->second));
    } // else default 0x0 RESERVED

    return sensorType;
}

inline static uint16_t getSensorNumberFromPath(const std::string& path)
{
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    details::getSensorNumMap(sensorNumMapPtr);
    if (!sensorNumMapPtr)
    {
        return invalidSensorNumber;
    }

    try
    {
        return sensorNumMapPtr->right.at(path);
    }
    catch (const std::out_of_range& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return invalidSensorNumber;
    }
}

inline static uint8_t getSensorEventTypeFromPath(const std::string& path)
{
    uint8_t sensorEventType = 0;
    std::string type = getSensorTypeStringFromPath(path);
    auto findSensor = sensorTypes.find(type.c_str());
    if (findSensor != sensorTypes.end())
    {
        sensorEventType = static_cast<uint8_t>(
            std::get<SensorEventTypeCodes>(findSensor->second));
    }
    else
    {
        // Support for additional reading types setting default to threshold
        sensorEventType = 0x1; // reading type = threshold
    }
    return sensorEventType;
}

inline static std::string getPathFromSensorNumber(uint16_t sensorNum,
                                                  uint8_t senType = 0xff)
{
    std::shared_ptr<SensorNumMap> sensorNumMapPtr;
    details::getSensorNumMap(sensorNumMapPtr);
    if (!sensorNumMapPtr)
    {
        return std::string();
    }

    try
    {
        if (senType == osCriticalStop) // check for os critical stop sensor type
        {
            for (auto it = sensorNumMapPtr->begin();
                 it != sensorNumMapPtr->end(); ++it)
            {
                size_t found = it->right.find("/os/");
                if (found != std::string::npos)
                {
                    return it->right;
                }
            }
        }

        return sensorNumMapPtr->left.at(sensorNum);
    }
    catch (const std::out_of_range& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return std::string();
    }
}

[[maybe_unused]] static uint8_t getEventType(const uint8_t sensorType)
{
    switch (sensorType)
    {
        case static_cast<uint8_t>(0x00):
        case static_cast<uint8_t>(0x01):
        case static_cast<uint8_t>(0x02):
        case static_cast<uint8_t>(0x03):
        case static_cast<uint8_t>(0x04):
            return 0x01;
        default:
            return 0x6f;
    }
}

namespace ipmi
{

static inline std::map<std::string, std::vector<std::string>>
    getObjectInterfaces(const char* path)
{
    std::map<std::string, std::vector<std::string>> interfacesResponse;
    std::vector<std::string> interfaces;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();

    sdbusplus::message_t getObjectMessage =
        dbus->new_method_call("xyz.openbmc_project.ObjectMapper",
                              "/xyz/openbmc_project/object_mapper",
                              "xyz.openbmc_project.ObjectMapper", "GetObject");
    getObjectMessage.append(path, interfaces);

    try
    {
        sdbusplus::message_t response = dbus->call(getObjectMessage);
        response.read(interfacesResponse);
    }
    catch (const std::exception& e)
    {
        // Disabling this log to reduce unnecessary error messages in the
        // journal. Enable if Debugging is Required
        /*phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to GetObject", phosphor::logging::entry("PATH=%s", path),
            phosphor::logging::entry("WHAT=%s", e.what())); */
    }

    return interfacesResponse;
}

static inline std::map<std::string, DbusVariant> getEntityManagerProperties(
    const char* path, const char* interface)
{
    std::map<std::string, DbusVariant> properties;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();

    sdbusplus::message_t getProperties =
        dbus->new_method_call("xyz.openbmc_project.EntityManager", path,
                              "org.freedesktop.DBus.Properties", "GetAll");
    getProperties.append(interface);

    try
    {
        sdbusplus::message_t response = dbus->call(getProperties);
        response.read(properties);
    }
    catch (const std::exception& e)
    {
        // Disabling this log to reduce unnecessary error messages in the
        // journal. Enable if Debugging is Required
        /*phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to GetAll", phosphor::logging::entry("PATH=%s", path),
            phosphor::logging::entry("INTF=%s", interface),
            phosphor::logging::entry("WHAT=%s", e.what())); */
    }

    return properties;
}

static inline const std::string* getSensorConfigurationInterface(
    const std::map<std::string, std::vector<std::string>>&
        sensorInterfacesResponse)
{
    auto entityManagerService =
        sensorInterfacesResponse.find("xyz.openbmc_project.EntityManager");
    if (entityManagerService == sensorInterfacesResponse.end())
    {
        return nullptr;
    }

    // Find the fan configuration first (fans can have multiple configuration
    // interfaces).
    for (const auto& entry : entityManagerService->second)
    {
        if (entry == "xyz.openbmc_project.Configuration.AspeedFan" ||
            entry == "xyz.openbmc_project.Configuration.I2CFan" ||
            entry == "xyz.openbmc_project.Configuration.NuvotonFan")
        {
            return &entry;
        }
    }

    for (const auto& entry : entityManagerService->second)
    {
        if (boost::algorithm::starts_with(entry,
                                          "xyz.openbmc_project.Configuration."))
        {
            return &entry;
        }
    }

    return nullptr;
}

// Follow Association properties for Sensor back to the Board dbus object to
// check for an EntityId and EntityInstance property.
static inline void updateIpmiFromAssociation(
    const std::string& path,
    [[maybe_unused]] const std::unordered_set<std::string>& ipmiDecoratorPaths,
    const SensorMap& sensorMap, uint8_t& entityId, uint8_t& entityInstance)
{
    namespace fs = std::filesystem;

    auto sensorAssociationObject =
        sensorMap.find("xyz.openbmc_project.Association.Definitions");
    if (sensorAssociationObject == sensorMap.end())
    {
        if constexpr (debug)
        {
            std::fprintf(stderr, "path=%s, no association interface found\n",
                         path.c_str());
        }

        return;
    }

    auto associationObject =
        sensorAssociationObject->second.find("Associations");
    if (associationObject == sensorAssociationObject->second.end())
    {
        if constexpr (debug)
        {
            std::fprintf(stderr, "path=%s, no association records found\n",
                         path.c_str());
        }

        return;
    }

    std::vector<Association> associationValues =
        std::get<std::vector<Association>>(associationObject->second);

    // loop through the Associations looking for the right one:
    for (const auto& entry : associationValues)
    {
        // forward, reverse, endpoint
        const std::string& forward = std::get<0>(entry);
        const std::string& reverse = std::get<1>(entry);
        const std::string& endpoint = std::get<2>(entry);

        // We only currently concern ourselves with chassis+all_sensors.
        if (!(forward == "chassis" && reverse == "all_sensors"))
        {
            continue;
        }

        // the endpoint is the board entry provided by
        // Entity-Manager. so let's grab its properties if it has
        // the right interface.

        // just try grabbing the properties first.
        std::map<std::string, DbusVariant> ipmiProperties =
            getEntityManagerProperties(
                endpoint.c_str(),
                "xyz.openbmc_project.Inventory.Decorator.Ipmi");

        auto entityIdProp = ipmiProperties.find("EntityId");
        auto entityInstanceProp = ipmiProperties.find("EntityInstance");
        if (entityIdProp != ipmiProperties.end())
        {
            entityId =
                static_cast<uint8_t>(std::get<uint64_t>(entityIdProp->second));
        }
        if (entityInstanceProp != ipmiProperties.end())
        {
            entityInstance = static_cast<uint8_t>(
                std::get<uint64_t>(entityInstanceProp->second));
        }

        // Now check the entity-manager entry for this sensor to see
        // if it has its own value and use that instead.
        //
        // In theory, checking this first saves us from checking
        // both, except in most use-cases identified, there won't be
        // a per sensor override, so we need to always check both.
        std::string sensorNameFromPath = fs::path(path).filename();

        std::string sensorConfigPath = endpoint + "/" + sensorNameFromPath;

        // Download the interfaces for the sensor from
        // Entity-Manager to find the name of the configuration
        // interface.
        std::map<std::string, std::vector<std::string>>
            sensorInterfacesResponse =
                getObjectInterfaces(sensorConfigPath.c_str());

        const std::string* configurationInterface =
            getSensorConfigurationInterface(sensorInterfacesResponse);

        // We didnt' find a configuration interface for this sensor, but we
        // followed the Association property to get here, so we're done
        // searching.
        if (!configurationInterface)
        {
            break;
        }

        // We found a configuration interface.
        std::map<std::string, DbusVariant> configurationProperties =
            getEntityManagerProperties(sensorConfigPath.c_str(),
                                       configurationInterface->c_str());

        entityIdProp = configurationProperties.find("EntityId");
        entityInstanceProp = configurationProperties.find("EntityInstance");
        if (entityIdProp != configurationProperties.end())
        {
            entityId =
                static_cast<uint8_t>(std::get<uint64_t>(entityIdProp->second));
        }
        if (entityInstanceProp != configurationProperties.end())
        {
            entityInstance = static_cast<uint8_t>(
                std::get<uint64_t>(entityInstanceProp->second));
        }

        // stop searching Association records.
        break;
    } // end for Association vectors.

    if constexpr (debug)
    {
        std::fprintf(stderr, "path=%s, entityId=%d, entityInstance=%d\n",
                     path.c_str(), entityId, entityInstance);
    }
}

// Fetch the ipmiDecoratorPaths to get the list of dbus objects that
// have ipmi decorator to prevent unnessary dbus call to fetch
inline std::optional<std::unordered_set<std::string>>& getIpmiDecoratorPaths(
    const std::optional<ipmi::Context::ptr>& ctx)
{
    static std::optional<std::unordered_set<std::string>> ipmiDecoratorPaths;

    if (!ctx.has_value() || ipmiDecoratorPaths != std::nullopt)
    {
        return ipmiDecoratorPaths;
    }

    boost::system::error_code ec;
    std::vector<std::string> paths =
        (*ctx)->bus->yield_method_call<std::vector<std::string>>(
            (*ctx)->yield, ec, "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths", "/",
            int32_t(0),
            std::array<const char*, 1>{
                "xyz.openbmc_project.Inventory.Decorator.Ipmi"});
    if (ec)
    {
        return ipmiDecoratorPaths;
    }

    ipmiDecoratorPaths =
        std::unordered_set<std::string>(paths.begin(), paths.end());
    return ipmiDecoratorPaths;
}

inline std::optional<std::unordered_set<std::string>>& getIpmiDecoratorPaths(
    const std::optional<ipmi::Context::ptr>& ctx);

} // namespace ipmi

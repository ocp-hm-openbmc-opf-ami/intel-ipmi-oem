/*
// Copyright (c) 2017 2018 Intel Corporation
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

#include "sensorcommands.hpp"

#include "commandutils.hpp"
#include "ipmi_to_redfish_hooks.hpp"
#include "sdrutils.hpp"
#include "sensorutils.hpp"
#include "storagecommands.hpp"
#include "types.hpp"
#include "xyz/openbmc_project/Logging/Entry/server.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <ipmid/api.hpp>
#include <ipmid/entity_map_json.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-ipmi-host/selutility.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Logging/SEL/error.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

using ErrLvl = sdbusplus::xyz::openbmc_project::Logging::server::Entry::Level;
auto sevLvl = ErrLvl::Informational;

namespace ipmi
{
using ManagedObjectType =
    std::map<sdbusplus::message::object_path,
             std::map<std::string, std::map<std::string, DbusVariant>>>;

static constexpr int sensorMapUpdatePeriod = 10;
static constexpr int sensorMapSdrUpdatePeriod = 60;

uint8_t pefSetInPro = 0;

// BMC I2C address is generally at 0x20
static constexpr uint8_t bmcI2CAddr = 0x20;

constexpr size_t maxSDRTotalSize =
    76; // Largest SDR Record Size (type 01) + SDR Overheader Size
constexpr static const uint32_t noTimestamp = 0xFFFFFFFF;

static uint16_t sdrReservationID;
static uint32_t sdrLastAdd = noTimestamp;
static uint32_t sdrLastRemove = noTimestamp;
static uint32_t sdrLastUpdate = noTimestamp;
static constexpr size_t lastRecordIndex = 0xFFFF;

constexpr bool debug = false;

// The IPMI spec defines four Logical Units (LUN), each capable of supporting
// 255 sensors. The 256 values assigned to LUN 2 are special and are not used
// for general purpose sensors. Each LUN reserves location 0xFF. The maximum
// number of IPMI sensors are LUN 0 + LUN 1 + LUN 2, less the reserved
// location.
static constexpr size_t maxIPMISensors = ((3 * 256) - (3 * 1));

static constexpr size_t lun0MaxSensorNum = 0xfe;
static constexpr size_t lun1MaxSensorNum = 0x1fe;
static constexpr size_t lun3MaxSensorNum = 0x3fe;
static constexpr int GENERAL_ERROR = -1;

static boost::container::flat_map<std::string, ManagedObjectType> SensorCache;

constexpr static std::array<std::pair<const char*, SensorUnits>, 5> sensorUnits{
    {{"temperature", SensorUnits::degreesC},
     {"voltage", SensorUnits::volts},
     {"current", SensorUnits::amps},
     {"fan_tach", SensorUnits::rpm},
     {"power", SensorUnits::watts}}};

void registerSensorFunctions() __attribute__((constructor));
ipmi_ret_t getSensorConnection(ipmi::Context::ptr ctx, uint8_t sensnum,
                               std::string& connection, std::string& path,
                               std::vector<std::string>* interfaces)
{
    // Retrieve the sensor tree
    auto& sensorTree = getSensorTree();
    if (!getSensorSubtree(sensorTree))
    {
        std::cerr << "Error: getSensorSubtree() failed!" << std::endl;
    }

    if (sensorTree.empty())
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    // Check for null context
    if (ctx == nullptr)
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    // Generate the sensor path based on sensnum
    path = getPathFromSensorNumber((ctx->lun << 8) | sensnum);

    if (path.empty())
    {
        return IPMI_CC_SENSOR_INVALID;
    }

    // Find the corresponding sensor in the tree
    bool found = false;
    for (const auto& sensor : sensorTree)
    {
        if (path == sensor.first)
        {
            connection = sensor.second.begin()->first;

            if (interfaces)
            {
                *interfaces = sensor.second.begin()->second;
            }

            found = true;
            break;
        }
    }

    // If no matching path is found, return an error
    if (!found)
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    return 0; // Success
}

SensorSubTree& getSensorTree()
{
    static SensorSubTree sensorTree;
    if (sensorTree.empty()) // Populate only if empty
    {
        getSensorSubtree(sensorTree);
    }
    return sensorTree;
}

// this keeps track of deassertions for sensor event status command. A
// deasertion can only happen if an assertion was seen first.
static boost::container::flat_map<
    std::string, boost::container::flat_map<std::string, std::optional<bool>>>
    thresholdDeassertMap;

static sdbusplus::bus::match_t thresholdChanged(
    *getSdBus(),
    "type='signal',member='PropertiesChanged',interface='org.freedesktop.DBus."
    "Properties',arg0namespace='xyz.openbmc_project.Sensor.Threshold'",
    [](sdbusplus::message_t& m) {
        boost::container::flat_map<std::string, ipmi::DbusVariant> values;
        m.read(std::string(), values);

        auto findAssert =
            std::find_if(values.begin(), values.end(), [](const auto& pair) {
                return pair.first.find("Alarm") != std::string::npos;
            });
        if (findAssert != values.end())
        {
            auto ptr = std::get_if<bool>(&(findAssert->second));
            if (ptr == nullptr)
            {
                if constexpr (debug)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "thresholdChanged: Assert non bool");
                }
                return;
            }
            if (*ptr)
            {
                if constexpr (debug)
                {
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "thresholdChanged: Assert",
                        phosphor::logging::entry("SENSOR=%s", m.get_path()));
                }
                thresholdDeassertMap[m.get_path()][findAssert->first] = *ptr;
            }
            else
            {
                auto& value =
                    thresholdDeassertMap[m.get_path()][findAssert->first];
                if (value)
                {
                    if constexpr (debug)
                    {
                        phosphor::logging::log<phosphor::logging::level::INFO>(
                            "thresholdChanged: deassert",
                            phosphor::logging::entry("SENSOR=%s",
                                                     m.get_path()));
                    }
                    value = *ptr;
                }
            }
        }
    });

namespace sensor
{
static constexpr const char* sensorInterface =
    "xyz.openbmc_project.Sensor.Value";
static constexpr const char* discreteInterface =
    "xyz.openbmc_project.Sensor.State";

bool getDiscreteStatus(const SensorMap& sensorMap,
                       [[maybe_unused]] const std::string path,
                       uint16_t& assertions)
{
    auto statusObject = sensorMap.find("xyz.openbmc_project.Sensor.State");
    if (statusObject != sensorMap.end())
    {
        auto status = statusObject->second.find("State");
        if (status != statusObject->second.end())
        {
            uint16_t state = std::get<uint16_t>(status->second);
            assertions |= state;
        }
    }
    return true;
}
} // namespace sensor

static void getSensorMaxMin(const SensorMap& sensorMap, double& max,
                            double& min)
{
    max = 127;
    min = -128;

    auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");
    auto critical =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
    auto warning =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    auto nonRecoverable =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.NonRecoverable");

    if (sensorObject != sensorMap.end())
    {
        auto maxMap = sensorObject->second.find("MaxValue");
        auto minMap = sensorObject->second.find("MinValue");

        if (maxMap != sensorObject->second.end())
        {
            max = std::visit(VariantToDoubleVisitor(), maxMap->second);
        }
        if (minMap != sensorObject->second.end())
        {
            min = std::visit(VariantToDoubleVisitor(), minMap->second);
        }
    }
    if (critical != sensorMap.end())
    {
        auto lower = critical->second.find("CriticalLow");
        auto upper = critical->second.find("CriticalHigh");
        if (lower != critical->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), lower->second);
            if (std::isfinite(value))
            {
                min = std::fmin(value, min);
            }
        }
        if (upper != critical->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), upper->second);
            if (std::isfinite(value))
            {
                max = std::fmax(value, max);
            }
        }
    }
    if (warning != sensorMap.end())
    {
        auto lower = warning->second.find("WarningLow");
        auto upper = warning->second.find("WarningHigh");
        if (lower != warning->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), lower->second);
            if (std::isfinite(value))
            {
                min = std::fmin(value, min);
            }
        }
        if (upper != warning->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), upper->second);
            if (std::isfinite(value))
            {
                max = std::fmax(value, max);
            }
        }
    }
    if (nonRecoverable != sensorMap.end())
    {
        auto lower = nonRecoverable->second.find("NonRecoverableLow");
        auto upper = nonRecoverable->second.find("NonRecoverableHigh");
        if (lower != nonRecoverable->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), lower->second);
            if (std::isfinite(value))
            {
                min = std::fmin(value, min);
            }
        }
        if (upper != nonRecoverable->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), upper->second);
            if (std::isfinite(value))
            {
                max = std::fmax(value, max);
            }
        }
    }
}

static bool getSensorMap(boost::asio::yield_context yield,
                         std::string sensorConnection, std::string sensorPath,
                         SensorMap& sensorMap,
                         int updatePeriod = sensorMapUpdatePeriod)
{
#ifdef FEATURE_HYBRID_SENSORS
    if (auto sensor = findStaticSensor(sensorPath);
        sensor != ipmi::sensor::sensors.end() &&
        getSensorEventTypeFromPath(sensorPath) !=
            static_cast<uint8_t>(SensorEventTypeCodes::threshold))
    {
        // If the incoming sensor is a discrete sensor, it might fail in
        // getManagedObjects(), return true, and use its own getFunc to get
        // value.
        return true;
    }
#endif
    static boost::container::flat_map<
        std::string, std::chrono::time_point<std::chrono::steady_clock>>
        updateTimeMap;

    auto updateFind = updateTimeMap.find(sensorConnection);
    auto lastUpdate = std::chrono::time_point<std::chrono::steady_clock>();
    if (updateFind != updateTimeMap.end())
    {
        lastUpdate = updateFind->second;
    }

    auto now = std::chrono::steady_clock::now();

    if (std::chrono::duration_cast<std::chrono::seconds>(now - lastUpdate)
            .count() > updatePeriod)
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        boost::system::error_code ec;
        auto managedObjects = dbus->yield_method_call<ManagedObjectType>(
            yield, ec, sensorConnection.c_str(), "/xyz/openbmc_project/sensors",
            "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "GetMangagedObjects for getSensorMap failed",
                phosphor::logging::entry("ERROR=%s", ec.message().c_str()));

            return false;
        }

        SensorCache[sensorConnection] = managedObjects;
        //  Update time after finish building the map which allow the
        //  data to be cached for updatePeriod plus the build time.
        updateTimeMap[sensorConnection] = std::chrono::steady_clock::now();
    }
    auto connection = SensorCache.find(sensorConnection);
    if (connection == SensorCache.end())
    {
        return false;
    }
    auto path = connection->second.find(sensorPath);
    if (path == connection->second.end())
    {
        return false;
    }
    sensorMap = path->second;
    return true;
}

/* sensor commands */
namespace meHealth
{
constexpr const char* busname = "xyz.openbmc_project.NodeManagerProxy";
constexpr const char* path = "/xyz/openbmc_project/status/me";
constexpr const char* interface = "xyz.openbmc_project.SetHealth";
constexpr const char* method = "SetHealth";
constexpr const char* critical = "critical";
constexpr const char* warning = "warning";
constexpr const char* ok = "ok";
} // namespace meHealth

static void setMeStatus(uint8_t eventData2, uint8_t eventData3, bool disable)
{
    constexpr const std::array<uint8_t, 10> critical = {
        0x1, 0x2, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xD, 0xE};
    constexpr const std::array<uint8_t, 5> warning = {0x3, 0xA, 0x13, 0x19,
                                                      0x1A};

    std::string state;
    if (std::find(critical.begin(), critical.end(), eventData2) !=
        critical.end())
    {
        state = meHealth::critical;
    }
    // special case 0x3 as we only care about a few states
    else if (eventData2 == 0x3)
    {
        if (eventData3 <= 0x2)
        {
            state = meHealth::warning;
        }
        else
        {
            return;
        }
    }
    else if (std::find(warning.begin(), warning.end(), eventData2) !=
             warning.end())
    {
        state = meHealth::warning;
    }
    else
    {
        return;
    }
    if (disable)
    {
        state = meHealth::ok;
    }

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    auto setHealth =
        dbus->new_method_call(meHealth::busname, meHealth::path,
                              meHealth::interface, meHealth::method);
    setHealth.append(std::to_string(static_cast<size_t>(eventData2)), state);
    try
    {
        dbus->call(setHealth);
    }
    catch (const sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set ME Health");
    }
}

bool constructDiscreteSdr(
    ipmi::Context::ptr ctx, uint16_t sensorNum, uint16_t recordID,
    const std::string& service, const std::string& path,
    const std::unordered_set<std::string>& ipmiDecoratorPaths,
    get_sdr::SensorDataCompactRecord& record)
{
    uint8_t sensorNumber = static_cast<uint8_t>(sensorNum);
    uint8_t lun = static_cast<uint8_t>(sensorNum >> 8);

    get_sdr::header::set_record_id(
        recordID, reinterpret_cast<get_sdr::SensorDataRecordHeader*>(&record));
    record.header.sdr_version = ipmiSdrVersion;
    record.header.record_type = get_sdr::SENSOR_DATA_COMPACT_RECORD;
    record.header.record_length = sizeof(get_sdr::SensorDataCompactRecord) -
                                  sizeof(get_sdr::SensorDataRecordHeader);
    record.key.owner_id = bmcI2CAddr;
    record.key.owner_lun = lun;
    record.key.sensor_number = sensorNumber;
    record.body.sensor_type = getSensorTypeFromPath(path);

    record.body.event_reading_type = getSensorEventTypeFromPath(path);
    SensorMap sensorMap;

    if (!getSensorMap(ctx->yield, service, path, sensorMap,
                      sensorMapSdrUpdatePeriod))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to update sensor map for discrete sensor",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", path.c_str()));
        return false;
    }
    uint8_t entityId = 0;
    uint8_t entityInstance = 0x01;

    // follow the association chain to get the parent board's entityid and
    // entityInstance
    updateIpmiFromAssociation(path, ipmiDecoratorPaths, sensorMap, entityId,
                              entityInstance);

    record.body.entity_id = entityId;
    record.body.entity_instance = entityInstance;
    std::string name;
    size_t nameStart = path.rfind("/");
    if (nameStart != std::string::npos)
    {
        name = path.substr(nameStart + 1, std::string::npos - nameStart);
    }
    std::replace(name.begin(), name.end(), '_', ' ');
    record.body.id_string_info = name.size();
    std::strncpy(record.body.id_string, name.c_str(),
                 sizeof(record.body.id_string));

    details::sdrStatsTable.updateName(sensorNumber, name);
    return true;
}

namespace sensor
{
/*
 * Handle every Sensor Data Record besides Type 01
 *
 * The D-Bus sensors work well for generating Type 01 SDRs.
 * After the Type 01 sensors are processed the remaining sensor types require
 * special handling. Each BMC vendor is going to have their own requirements for
 * insertion of non-Type 01 records.
 * Manage non-Type 01 records:
 *
 * Create a new file: dbus-sdr/sensorcommands_oem.cpp
 * Populate it with the two weakly linked functions below, without adding the
 * 'weak' attribute definition prior to the function definition.
 *    getOtherSensorsCount(...)
 *    getOtherSensorsDataRecord(...)
 *    Example contents are provided in the weak definitions below
 *    Enable 'sensors-oem' in your phosphor-ipmi-host bbappend file
 *      'EXTRA_OEMESON:append = " -Dsensors-oem=enabled"'
 * The contents of the sensorcommands_oem.cpp file will then override the code
 * provided below.
 */

size_t getOtherSensorsCount(ipmi::Context::ptr ctx) __attribute__((weak));
size_t getOtherSensorsCount(ipmi::Context::ptr ctx)
{
    size_t fruCount = 0;

    ipmi::Cc ret = ipmi::storage::getFruSdrCount(ctx, fruCount);
    if (ret != ipmi::ccSuccess)
    {
        lg2::error("getOtherSensorsCount: getFruSdrCount error");
        return std::numeric_limits<size_t>::max();
    }

    const auto& entityRecords =
        ipmi::sensor::EntityInfoMapContainer::getContainer()
            ->getIpmiEntityRecords();
    size_t entityCount = entityRecords.size();

    return fruCount + ipmi::storage::type12Count + entityCount;
}

int getOtherSensorsDataRecord(ipmi::Context::ptr ctx, uint16_t recordID,
                              std::vector<uint8_t>& recordData)
    __attribute__((weak));
int getOtherSensorsDataRecord(ipmi::Context::ptr ctx, uint16_t recordID,
                              std::vector<uint8_t>& recordData)
{
    size_t otherCount{ipmi::sensor::getOtherSensorsCount(ctx)};
    if (otherCount == std::numeric_limits<size_t>::max())
    {
        return GENERAL_ERROR;
    }
    const auto& entityRecords =
        ipmi::sensor::EntityInfoMapContainer::getContainer()
            ->getIpmiEntityRecords();

    size_t SdrIndex(recordID - getNumberOfSensors());
    size_t entityCount{entityRecords.size()};
    size_t fruCount{otherCount - ipmi::storage::type12Count - entityCount};

    if (SdrIndex > otherCount)
    {
        return std::numeric_limits<int>::min();
    }
    else if (SdrIndex >= fruCount + ipmi::storage::type12Count)
    {
        // handle type 8 entity map records
        ipmi::sensor::EntityInfoMap::const_iterator entity =
            entityRecords.find(static_cast<uint8_t>(
                SdrIndex - fruCount - ipmi::storage::type12Count));

        if (entity == entityRecords.end())
        {
            return GENERAL_ERROR;
        }
        recordData = ipmi::storage::getType8SDRs(entity, recordID);
    }
    else if (SdrIndex >= fruCount)
    {
        // handle type 12 hardcoded records
        size_t type12Index = SdrIndex - fruCount;
        if (type12Index >= ipmi::storage::type12Count)
        {
            lg2::error("getSensorDataRecord: type12Index error");
            return GENERAL_ERROR;
        }
        recordData = ipmi::storage::getType12SDRs(type12Index, recordID);
    }
    else
    {
        // handle fru records
        get_sdr::SensorDataFruRecord data;
        if (ipmi::Cc ret = ipmi::storage::getFruSdrs(ctx, SdrIndex, data);
            ret != IPMI_CC_OK)
        {
            return GENERAL_ERROR;
        }
        data.header.record_id_msb = recordID >> 8;
        data.header.record_id_lsb = recordID & 0xFF;
        recordData.insert(recordData.end(), reinterpret_cast<uint8_t*>(&data),
                          reinterpret_cast<uint8_t*>(&data) + sizeof(data));
    }
    return 0;
}

} // namespace sensor
ipmi::RspType<> ipmiSenPlatformEvent(ipmi::Context::ptr ctx,
                                     ipmi::message::Payload& p)
{
    constexpr const uint8_t meId = 0x2C;
    constexpr const uint8_t meSensorNum = 0x17;
    constexpr const uint8_t disabled = 0x80;

    uint8_t sysgeneratorID = 0;
    uint8_t evmRev = 0;
    uint8_t sensorType = 0;
    uint8_t sensorNum = 0;
    uint8_t eventType = 0;
    uint8_t eventData1 = 0;
    std::optional<uint8_t> eventData2 = 0;
    std::optional<uint8_t> eventData3 = 0;
    uint16_t generatorID = 0;
    ipmi::ChannelInfo chInfo;
    std::string sensorPath;
    bool assert = false;

    if (ipmi::getChannelInfo(ctx->channel, chInfo) != ipmi::ccSuccess)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get Channel Info",
            phosphor::logging::entry("CHANNEL=%d", ctx->channel));
        return ipmi::responseUnspecifiedError();
    }

    if (static_cast<ipmi::EChannelMediumType>(chInfo.mediumType) ==
        ipmi::EChannelMediumType::systemInterface)
    {
        p.unpack(sysgeneratorID, evmRev, sensorType, sensorNum, eventType,
                 eventData1, eventData2, eventData3);
        constexpr const uint8_t isSoftwareID = 0x01;
        if (!(sysgeneratorID & isSoftwareID))
        {
            return ipmi::responseInvalidFieldRequest();
        }
        // Refer to IPMI Spec Table 32: SEL Event Records
        generatorID = (ctx->channel << 12) // Channel
                      | (0x0 << 10)        // Reserved
                      | (0x0 << 8)         // 0x0 for sys-soft ID
                      | sysgeneratorID;

        assert = eventType & directionMask ? false : true;
        sensorPath = getPathFromSensorNumber(sensorNum, sensorType);
    }
    else
    {
        p.unpack(evmRev, sensorType, sensorNum, eventType, eventData1,
                 eventData2, eventData3);
        // Refer to IPMI Spec Table 32: SEL Event Records
        generatorID = (ctx->channel << 12)      // Channel
                      | (0x0 << 10)             // Reserved
                      | ((ctx->lun & 0x3) << 8) // Lun
                      | (ctx->rqSA << 1);

        assert = eventType & directionMask ? false : true;
        sensorPath = getPathFromSensorNumber(sensorNum, sensorType);
    }

    if (!p.fullyUnpacked())
    {
        return ipmi::responseReqDataLenInvalid();
    }

    // Check for valid evmRev and Sensor Type(per Table 42 of spec)
    if (evmRev != 0x04)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    if ((sensorType > 0x2C) && (sensorType < 0xC0))
    {
        return ipmi::responseInvalidFieldRequest();
    }
    // adding event message to SEL
    std::vector<uint8_t> eventData{eventData1, eventData2.value_or(0xFF),
                                   eventData3.value_or(0xFF)};
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();

    static constexpr auto systemRecordType = 0x02;
    std::string messageID = "";
    auto selDataStr = ipmi::sel::toHexStr(eventData);

    std::map<std::string, std::string> addData;
    addData["SENSOR_DATA"] = selDataStr.c_str();
    addData["SENSOR_PATH"] = sensorPath;
    addData["EVENT_DIR"] = std::to_string(assert);
    addData["GENERATOR_ID"] = std::to_string(generatorID);
    addData["RECORD_TYPE"] = std::to_string(systemRecordType);
    addData["SENSOR_TYPE"] = std::to_string(sensorType);

    std::string redfishMessage = intel_oem::ipmi::sel::checkRedfishMessage(
        generatorID, sensorType, sensorNum, eventType, eventData1);
    try
    {
        std::string service =
            ipmi::getService(*bus, ipmiSELAddInterface, ipmiSELPath);
        auto addSEL = bus->new_method_call(service.c_str(), ipmiSELPath,
                                           ipmiSELAddInterface, "IpmiSelAdd");
        addSEL.append(redfishMessage, sensorPath.c_str(), eventData, assert,
                      generatorID, addData);
        bus->call(addSEL);
        cancelSELReservation();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Failed to create D-Bus log entry for SEL, ERROR="
                  << e.what() << "\n";
    }

    if (static_cast<uint8_t>(generatorID) == meId && sensorNum == meSensorNum &&
        eventData2 && eventData3)
    {
        setMeStatus(*eventData2, *eventData3, (eventType & disabled));
    }
    return ipmi::responseSuccess();
}

/** @brief implements the Get Sensor Type command
 *  @returns the sensor type value and Event/Reading type code
 */

ipmi::RspType<uint8_t, // sensor type
              uint8_t> // event/reading type code
    ipmiGetSensorTypeCmd(uint8_t SensorNum)
{
    std::string sensorPath;
    uint8_t sensorType;
    uint8_t eventType;

    try
    {
        sensorPath = getPathFromSensorNumber(SensorNum);
        if (sensorPath.empty())
        {
            return ipmi::response(ccSensorInvalid);
        }
        sensorType = getSensorTypeFromPath(sensorPath);
        eventType = getSensorEventTypeFromPath(sensorPath);
    }
    catch (std::exception&)
    {
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(sensorType, eventType);
}

ipmi::RspType<uint8_t, uint8_t, uint8_t, std::optional<uint8_t>>
    ipmiSenGetSensorReading(ipmi::Context::ptr ctx, uint8_t sensnum)
{
    std::string connection;
    std::string path;
    if (sensnum == reservedSensorNumber)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    auto status = getSensorConnection(ctx, sensnum, connection, path);

    if (status)
    {
        return ipmi::response(status);
    }

    SensorMap sensorMap;
    if (!getSensorMap(ctx->yield, connection, path, sensorMap))
    {
        return ipmi::responseResponseError();
    }

    // To handle Discrete sensor
    auto discInterface = sensorMap.find(sensor::discreteInterface);
    if (discInterface != sensorMap.end())
    {
        uint16_t assertions = 0;

        if (!sensor::getDiscreteStatus(sensorMap, path, assertions))
        {
            return ipmi::responseResponseError();
        }

        uint8_t value = 0;
        uint8_t operation = 0;
        uint8_t eventByte1 = (assertions & 0xFF);
        uint8_t eventByte2 = (assertions >> 8);
        operation |=
            static_cast<uint8_t>(IPMISensorReadingByte2::sensorScanningEnable);

        return ipmi::responseSuccess(value, operation, eventByte1, eventByte2);
    }

#ifdef FEATURE_HYBRID_SENSORS
    if (auto sensor = findStaticSensor(path);
        sensor != ipmi::sensor::sensors.end() &&
        getSensorEventTypeFromPath(path) !=
            static_cast<uint8_t>(SensorEventTypeCodes::threshold))
    {
        if (ipmi::sensor::Mutability::Read !=
            (sensor->second.mutability & ipmi::sensor::Mutability::Read))
        {
            return ipmi::responseIllegalCommand();
        }

        uint8_t operation;
        try
        {
            ipmi::sensor::GetSensorResponse getResponse =
                sensor->second.getFunc(sensor->second);

            if (getResponse.readingOrStateUnavailable)
            {
                operation |= static_cast<uint8_t>(
                    IPMISensorReadingByte2::readingStateUnavailable);
            }
            if (getResponse.scanningEnabled)
            {
                operation |= static_cast<uint8_t>(
                    IPMISensorReadingByte2::sensorScanningEnable);
            }
            if (getResponse.allEventMessagesEnabled)
            {
                operation |= static_cast<uint8_t>(
                    IPMISensorReadingByte2::eventMessagesEnable);
            }
            return ipmi::responseSuccess(
                getResponse.reading, operation,
                getResponse.thresholdLevelsStates,
                getResponse.discreteReadingSensorStates);
        }
        catch (const std::exception& e)
        {
            operation |= static_cast<uint8_t>(
                IPMISensorReadingByte2::readingStateUnavailable);
            return ipmi::responseSuccess(0, operation, 0, std::nullopt);
        }
    }
#endif

    auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");

    if (sensorObject == sensorMap.end() ||
        sensorObject->second.find("Value") == sensorObject->second.end())
    {
        return ipmi::responseResponseError();
    }
    auto& valueVariant = sensorObject->second["Value"];
    double reading = std::visit(VariantToDoubleVisitor(), valueVariant);

    double max = 0;
    double min = 0;
    getSensorMaxMin(sensorMap, max, min);

    int16_t mValue = 0;
    int16_t bValue = 0;
    int8_t rExp = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
    {
        return ipmi::responseResponseError();
    }

    uint8_t value =
        scaleIPMIValueFromDouble(reading, mValue, rExp, bValue, bExp, bSigned);
    uint8_t operation =
        static_cast<uint8_t>(IPMISensorReadingByte2::sensorScanningEnable);
    operation |=
        static_cast<uint8_t>(IPMISensorReadingByte2::eventMessagesEnable);
    bool notReading = std::isnan(reading);

    if (!notReading)
    {
        auto availableObject =
            sensorMap.find("xyz.openbmc_project.State.Decorator.Availability");
        if (availableObject != sensorMap.end())
        {
            auto findAvailable = availableObject->second.find("Available");
            if (findAvailable != availableObject->second.end())
            {
                bool* available = std::get_if<bool>(&(findAvailable->second));
                if (available && !(*available))
                {
                    notReading = true;
                }
            }
        }
    }

    if (notReading)
    {
        operation |= static_cast<uint8_t>(
            IPMISensorReadingByte2::readingStateUnavailable);
    }
    if constexpr (details::enableInstrumentation)
    {
        int byteValue;
        if (bSigned)
        {
            byteValue = static_cast<int>(static_cast<int8_t>(value));
        }
        else
        {
            byteValue = static_cast<int>(static_cast<uint8_t>(value));
        }

        // Keep stats on the reading just obtained, even if it is "NaN"
        if (details::sdrStatsTable.updateReading(sensnum, reading, byteValue))
        {
            // This is the first reading, show the coefficients
            double step = (max - min) / 255.0;
            std::cerr << "IPMI sensor "
                      << details::sdrStatsTable.getName(sensnum)
                      << ": Range min=" << min << " max=" << max
                      << ", step=" << step
                      << ", Coefficients mValue=" << static_cast<int>(mValue)
                      << " rExp=" << static_cast<int>(rExp)
                      << " bValue=" << static_cast<int>(bValue)
                      << " bExp=" << static_cast<int>(bExp)
                      << " bSigned=" << static_cast<int>(bSigned) << "\n";
        }
    }

    uint8_t thresholds = 0;

    auto warningObject =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    if (warningObject != sensorMap.end())
    {
        auto alarmHigh = warningObject->second.find("WarningAlarmHigh");
        auto alarmLow = warningObject->second.find("WarningAlarmLow");
        if (alarmHigh != warningObject->second.end())
        {
            if (std::get<bool>(alarmHigh->second))
            {
                thresholds |= static_cast<uint8_t>(
                    IPMISensorReadingByte3::upperNonCritical);
            }
        }
        if (alarmLow != warningObject->second.end())
        {
            if (std::get<bool>(alarmLow->second))
            {
                thresholds |= static_cast<uint8_t>(
                    IPMISensorReadingByte3::lowerNonCritical);
            }
        }
    }

    auto criticalObject =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
    if (criticalObject != sensorMap.end())
    {
        auto alarmHigh = criticalObject->second.find("CriticalAlarmHigh");
        auto alarmLow = criticalObject->second.find("CriticalAlarmLow");
        if (alarmHigh != criticalObject->second.end())
        {
            if (std::get<bool>(alarmHigh->second))
            {
                thresholds |=
                    static_cast<uint8_t>(IPMISensorReadingByte3::upperCritical);
            }
        }
        if (alarmLow != criticalObject->second.end())
        {
            if (std::get<bool>(alarmLow->second))
            {
                thresholds |=
                    static_cast<uint8_t>(IPMISensorReadingByte3::lowerCritical);
            }
        }
    }
    auto nonRecoverableObject =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.NonRecoverable");
    if (nonRecoverableObject != sensorMap.end())
    {
        auto alarmHigh =
            nonRecoverableObject->second.find("NonRecoverableAlarmHigh");
        auto alarmLow =
            nonRecoverableObject->second.find("NonRecoverableAlarmLow");
        if (alarmHigh != nonRecoverableObject->second.end())
        {
            if (std::get<bool>(alarmHigh->second))
            {
                thresholds |= static_cast<uint8_t>(
                    IPMISensorReadingByte3::upperNonRecoverable);
            }
        }
        if (alarmLow != nonRecoverableObject->second.end())
        {
            if (std::get<bool>(alarmLow->second))
            {
                thresholds |= static_cast<uint8_t>(
                    IPMISensorReadingByte3::lowerNonRecoverable);
            }
        }
    }
    // no discrete as of today so optional byte is never returned
    return ipmi::responseSuccess(value, operation, thresholds, std::nullopt);
}

/** @brief implements the Set Sensor threshold command
 *  @param sensorNumber        - sensor number
 *  @param lowerNonCriticalThreshMask
 *  @param lowerCriticalThreshMask
 *  @param lowerNonRecovThreshMask
 *  @param upperNonCriticalThreshMask
 *  @param upperCriticalThreshMask
 *  @param upperNonRecovThreshMask
 *  @param reserved
 *  @param lowerNonCritical    - lower non-critical threshold
 *  @param lowerCritical       - Lower critical threshold
 *  @param lowerNonRecoverable - Lower non recovarable threshold
 *  @param upperNonCritical    - Upper non-critical threshold
 *  @param upperCritical       - Upper critical
 *  @param upperNonRecoverable - Upper Non-recoverable
 *
 *  @returns IPMI completion code
 */
ipmi::RspType<> ipmiSenSetSensorThresholds(
    ipmi::Context::ptr ctx, uint8_t sensorNum, bool lowerNonCriticalThreshMask,
    bool lowerCriticalThreshMask, bool lowerNonRecovThreshMask,
    bool upperNonCriticalThreshMask, bool upperCriticalThreshMask,
    bool upperNonRecovThreshMask, [[maybe_unused]] uint2_t reserved,
    uint8_t lowerNonCritical, uint8_t lowerCritical,
    [[maybe_unused]] uint8_t lowerNonRecoverable, uint8_t upperNonCritical,
    uint8_t upperCritical, [[maybe_unused]] uint8_t upperNonRecoverable)
{
    if (sensorNum == reservedSensorNumber)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::string connection;
    std::string path;

    ipmi::Cc status = getSensorConnection(ctx, sensorNum, connection, path);
    if (status)
    {
        return ipmi::response(status);
    }

    // lower nc and upper nc not suppported on any sensor
    if (lowerNonRecovThreshMask || upperNonRecovThreshMask)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // if none of the threshold mask are set, nothing to do
    if (!(lowerNonCriticalThreshMask | lowerCriticalThreshMask |
          lowerNonRecovThreshMask | upperNonCriticalThreshMask |
          upperCriticalThreshMask | upperNonRecovThreshMask))
    {
        return ipmi::responseSuccess();
    }

    SensorMap sensorMap;
    // DbusInterfaceMap sensorMap;
    if (!getSensorMap(ctx->yield, connection, path, sensorMap))
    {
        return ipmi::responseResponseError();
    }

    double max = 0;
    double min = 0;
    getSensorMaxMin(sensorMap, max, min);

    int16_t mValue = 0;
    int16_t bValue = 0;
    int8_t rExp = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
    {
        return ipmi::responseResponseError();
    }

    // store a vector of property name, value to set, and interface
    std::vector<std::tuple<std::string, uint8_t, std::string>> thresholdsToSet;

    // define the indexes of the tuple
    constexpr uint8_t propertyName = 0;
    constexpr uint8_t thresholdValue = 1;
    constexpr uint8_t interface = 2;
    // verifiy all needed fields are present
    if (lowerCriticalThreshMask || upperCriticalThreshMask)
    {
        auto findThreshold =
            sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
        if (findThreshold == sensorMap.end())
        {
            return ipmi::responseInvalidFieldRequest();
        }
        if (lowerCriticalThreshMask)
        {
            auto findLower = findThreshold->second.find("CriticalLow");
            if (findLower == findThreshold->second.end())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            thresholdsToSet.emplace_back("CriticalLow", lowerCritical,
                                         findThreshold->first);
        }
        if (upperCriticalThreshMask)
        {
            auto findUpper = findThreshold->second.find("CriticalHigh");
            if (findUpper == findThreshold->second.end())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            thresholdsToSet.emplace_back("CriticalHigh", upperCritical,
                                         findThreshold->first);
        }
    }
    if (lowerNonCriticalThreshMask || upperNonCriticalThreshMask)
    {
        auto findThreshold =
            sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
        if (findThreshold == sensorMap.end())
        {
            return ipmi::responseInvalidFieldRequest();
        }
        if (lowerNonCriticalThreshMask)
        {
            auto findLower = findThreshold->second.find("WarningLow");
            if (findLower == findThreshold->second.end())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            thresholdsToSet.emplace_back("WarningLow", lowerNonCritical,
                                         findThreshold->first);
        }
        if (upperNonCriticalThreshMask)
        {
            auto findUpper = findThreshold->second.find("WarningHigh");
            if (findUpper == findThreshold->second.end())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            thresholdsToSet.emplace_back("WarningHigh", upperNonCritical,
                                         findThreshold->first);
        }
    }
    if (lowerNonRecovThreshMask || upperNonRecovThreshMask)
    {
        auto findThreshold = sensorMap.find(
            "xyz.openbmc_project.Sensor.Threshold.NonRecoverable");
        if (findThreshold == sensorMap.end())
        {
            return ipmi::responseInvalidFieldRequest();
        }
        if (lowerNonRecovThreshMask)
        {
            auto findLower = findThreshold->second.find("NonRecoverableLow");
            if (findLower == findThreshold->second.end())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            thresholdsToSet.emplace_back(
                "NonRecoverableLow", lowerNonRecoverable, findThreshold->first);
        }
        if (upperNonRecovThreshMask)
        {
            auto findUpper = findThreshold->second.find("NonRecoverableHigh");
            if (findUpper == findThreshold->second.end())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            thresholdsToSet.emplace_back("NonRecoverableHigh",
                                         upperNonRecoverable,
                                         findThreshold->first);
        }
    }
    for (const auto& property : thresholdsToSet)
    {
        // from section 36.3 in the IPMI Spec, assume all linear
        double valueToSet = ((mValue * std::get<thresholdValue>(property)) +
                             (bValue * std::pow(10.0, bExp))) *
                            std::pow(10.0, rExp);

        setDbusProperty(
            *getSdBus(), connection, path, std::get<interface>(property),
            std::get<propertyName>(property), ipmi::Value(valueToSet));
    }
    return ipmi::responseSuccess();
}

IPMIThresholds getIPMIThresholds(const SensorMap& sensorMap)
{
    IPMIThresholds resp;
    auto warningInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    auto criticalInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
    auto nonRecoverableInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.NonRecoverable");

    if ((warningInterface != sensorMap.end()) ||
        (criticalInterface != sensorMap.end()) ||
        (nonRecoverableInterface != sensorMap.end()))
    {
        auto sensorPair = sensorMap.find("xyz.openbmc_project.Sensor.Value");

        if (sensorPair == sensorMap.end())
        {
            // should not have been able to find a sensor not implementing
            // the sensor object
            throw std::runtime_error("Invalid sensor map");
        }

        double max = 0;
        double min = 0;
        getSensorMaxMin(sensorMap, max, min);

        int16_t mValue = 0;
        int16_t bValue = 0;
        int8_t rExp = 0;
        int8_t bExp = 0;
        bool bSigned = false;

        if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
        {
            throw std::runtime_error("Invalid sensor atrributes");
        }
        if (warningInterface != sensorMap.end())
        {
            auto& warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningHigh");
            auto warningLow = warningMap.find("WarningLow");

            if (warningHigh != warningMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), warningHigh->second);
                if (std::isfinite(value))
                {
                    resp.warningHigh = scaleIPMIValueFromDouble(
                        value, mValue, rExp, bValue, bExp, bSigned);
                }
            }
            if (warningLow != warningMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), warningLow->second);
                if (std::isfinite(value))
                {
                    resp.warningLow = scaleIPMIValueFromDouble(
                        value, mValue, rExp, bValue, bExp, bSigned);
                }
            }
        }
        if (criticalInterface != sensorMap.end())
        {
            auto& criticalMap = criticalInterface->second;

            auto criticalHigh = criticalMap.find("CriticalHigh");
            auto criticalLow = criticalMap.find("CriticalLow");

            if (criticalHigh != criticalMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), criticalHigh->second);
                if (std::isfinite(value))
                {
                    resp.criticalHigh = scaleIPMIValueFromDouble(
                        value, mValue, rExp, bValue, bExp, bSigned);
                }
            }
            if (criticalLow != criticalMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), criticalLow->second);
                if (std::isfinite(value))
                {
                    resp.criticalLow = scaleIPMIValueFromDouble(
                        value, mValue, rExp, bValue, bExp, bSigned);
                }
            }
        }
        if (nonRecoverableInterface != sensorMap.end())
        {
            auto& nonRecoverableMap = nonRecoverableInterface->second;

            auto nonRecoverableHigh =
                nonRecoverableMap.find("NonRecoverableHigh");
            auto nonRecoverableLow =
                nonRecoverableMap.find("NonRecoverableLow");

            if (nonRecoverableHigh != nonRecoverableMap.end())
            {
                double value = std::visit(VariantToDoubleVisitor(),
                                          nonRecoverableHigh->second);
                if (std::isfinite(value))
                {
                    resp.nonRecoverableHigh = scaleIPMIValueFromDouble(
                        value, mValue, rExp, bValue, bExp, bSigned);
                }
            }
            if (nonRecoverableLow != nonRecoverableMap.end())
            {
                double value = std::visit(VariantToDoubleVisitor(),
                                          nonRecoverableLow->second);
                if (std::isfinite(value))
                {
                    resp.nonRecoverableLow = scaleIPMIValueFromDouble(
                        value, mValue, rExp, bValue, bExp, bSigned);
                }
            }
        }
    }
    return resp;
}

ipmi::RspType<uint8_t, // readable
              uint8_t, // lowerNCrit
              uint8_t, // lowerCrit
              uint8_t, // lowerNrecoverable
              uint8_t, // upperNC
              uint8_t, // upperCrit
              uint8_t> // upperNRecoverable
    ipmiSenGetSensorThresholds(ipmi::Context::ptr ctx, uint8_t sensorNumber)
{
    std::string connection;
    std::string path;

    if (sensorNumber == reservedSensorNumber)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    auto status = getSensorConnection(ctx, sensorNumber, connection, path);
    if (status)
    {
        return ipmi::response(status);
    }

    SensorMap sensorMap;
    if (!getSensorMap(ctx->yield, connection, path, sensorMap))
    {
        return ipmi::responseResponseError();
    }

    IPMIThresholds thresholdData;
    try
    {
        thresholdData = getIPMIThresholds(sensorMap);
    }
    catch (const std::exception&)
    {
        return ipmi::responseResponseError();
    }

    uint8_t readable = 0;
    uint8_t lowerNC = 0;
    uint8_t lowerCritical = 0;
    uint8_t lowerNonRecoverable = 0;
    uint8_t upperNC = 0;
    uint8_t upperCritical = 0;
    uint8_t upperNonRecoverable = 0;

    if (thresholdData.warningHigh)
    {
        readable |=
            1 << static_cast<uint8_t>(IPMIThresholdRespBits::upperNonCritical);
        upperNC = *thresholdData.warningHigh;
    }
    if (thresholdData.warningLow)
    {
        readable |=
            1 << static_cast<uint8_t>(IPMIThresholdRespBits::lowerNonCritical);
        lowerNC = *thresholdData.warningLow;
    }

    if (thresholdData.criticalHigh)
    {
        readable |=
            1 << static_cast<uint8_t>(IPMIThresholdRespBits::upperCritical);
        upperCritical = *thresholdData.criticalHigh;
    }
    if (thresholdData.criticalLow)
    {
        readable |=
            1 << static_cast<uint8_t>(IPMIThresholdRespBits::lowerCritical);
        lowerCritical = *thresholdData.criticalLow;
    }
    if (thresholdData.nonRecoverableHigh)
    {
        readable |= 1 << static_cast<uint8_t>(
                        IPMIThresholdRespBits::upperNonRecoverable);
        upperNonRecoverable = *thresholdData.nonRecoverableHigh;
    }
    if (thresholdData.nonRecoverableLow)
    {
        readable |= 1 << static_cast<uint8_t>(
                        IPMIThresholdRespBits::lowerNonRecoverable);
        lowerNonRecoverable = *thresholdData.nonRecoverableLow;
    }
    return ipmi::responseSuccess(readable, lowerNC, lowerCritical,
                                 lowerNonRecoverable, upperNC, upperCritical,
                                 upperNonRecoverable);
}

/** @brief implements the get Sensor event enable command
 *  @param sensorNumber - sensor number
 *
 *  @returns IPMI completion code plus response data
 *   - enabled               - Sensor Event messages
 *   - assertionEnabledLsb   - Assertion event messages
 *   - assertionEnabledMsb   - Assertion event messages
 *   - deassertionEnabledLsb - Deassertion event messages
 *   - deassertionEnabledMsb - Deassertion event messages
 */

ipmi::RspType<uint8_t, // enabled
              uint8_t, // assertionEnabledLsb
              uint8_t, // assertionEnabledMsb
              uint8_t, // deassertionEnabledLsb
              uint8_t> // deassertionEnabledMsb
    ipmiSenGetSensorEventEnable(ipmi::Context::ptr ctx, uint8_t sensorNum)
{
    std::string connection;
    std::string path;

    uint8_t enabled = 0;
    uint8_t assertionEnabledLsb = 0;
    uint8_t assertionEnabledMsb = 0;
    uint8_t deassertionEnabledLsb = 0;
    uint8_t deassertionEnabledMsb = 0;

    if (sensorNum == reservedSensorNumber)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    auto status = getSensorConnection(ctx, sensorNum, connection, path);
    if (status)
    {
        return ipmi::response(status);
    }
#ifdef FEATURE_HYBRID_SENSORS
    if (auto sensor = findStaticSensor(path);
        sensor != ipmi::sensor::sensors.end() &&
        getSensorEventTypeFromPath(path) !=
            static_cast<uint8_t>(SensorEventTypeCodes::threshold))
    {
        enabled = static_cast<uint8_t>(
            IPMISensorEventEnableByte2::sensorScanningEnable);
        uint16_t assertionEnabled = 0;
        for (auto& offsetValMap : sensor->second.propertyInterfaces.begin()
                                      ->second.begin()
                                      ->second.second)
        {
            assertionEnabled |= (1 << offsetValMap.first);
        }
        assertionEnabledLsb = static_cast<uint8_t>((assertionEnabled & 0xFF));
        assertionEnabledMsb =
            static_cast<uint8_t>(((assertionEnabled >> 8) & 0xFF));

        return ipmi::responseSuccess(enabled, assertionEnabledLsb,
                                     assertionEnabledMsb, deassertionEnabledLsb,
                                     deassertionEnabledMsb);
    }
#endif

    SensorMap sensorMap;
    if (!getSensorMap(ctx->yield, connection, path, sensorMap))
    {
        return ipmi::responseResponseError();
    }

    auto warningInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    auto criticalInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
    auto nonRecoverableInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.NonRecoverable");
    if ((warningInterface != sensorMap.end()) ||
        (criticalInterface != sensorMap.end()) ||
        (nonRecoverableInterface != sensorMap.end()))
    {
        enabled = static_cast<uint8_t>(
            IPMISensorEventEnableByte2::sensorScanningEnable);
        if (warningInterface != sensorMap.end())
        {
            auto& warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningHigh");
            auto warningLow = warningMap.find("WarningLow");
            if (warningHigh != warningMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), warningHigh->second);
                if (std::isfinite(value))
                {
                    assertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            upperNonCriticalGoingHigh);
                    deassertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            upperNonCriticalGoingLow);
                }
            }
            if (warningLow != warningMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), warningLow->second);
                if (std::isfinite(value))
                {
                    assertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            lowerNonCriticalGoingLow);
                    deassertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            lowerNonCriticalGoingHigh);
                }
            }
        }
        if (criticalInterface != sensorMap.end())
        {
            auto& criticalMap = criticalInterface->second;

            auto criticalHigh = criticalMap.find("CriticalHigh");
            auto criticalLow = criticalMap.find("CriticalLow");

            if (criticalHigh != criticalMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), criticalHigh->second);
                if (std::isfinite(value))
                {
                    assertionEnabledMsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            upperCriticalGoingHigh);
                    deassertionEnabledMsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::upperCriticalGoingLow);
                }
            }
            if (criticalLow != criticalMap.end())
            {
                double value =
                    std::visit(VariantToDoubleVisitor(), criticalLow->second);
                if (std::isfinite(value))
                {
                    assertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::lowerCriticalGoingLow);
                    deassertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            lowerCriticalGoingHigh);
                }
            }
        }
        if (nonRecoverableInterface != sensorMap.end())
        {
            auto& nonRecoverableMap = nonRecoverableInterface->second;

            auto nonRecoverabHigh =
                nonRecoverableMap.find("NonRecoverableHigh");
            auto nonRecoverabLow = nonRecoverableMap.find("NonRecoverableLow");
            if (nonRecoverabHigh != nonRecoverableMap.end())
            {
                double value = std::visit(VariantToDoubleVisitor(),
                                          nonRecoverabHigh->second);
                if (std::isfinite(value))
                {
                    assertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            upperNonRecoverableGoingHigh);
                    deassertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            upperNonRecoverableGoingLow);
                }
            }
            if (nonRecoverabLow != nonRecoverableMap.end())
            {
                double value = std::visit(VariantToDoubleVisitor(),
                                          nonRecoverabLow->second);
                if (std::isfinite(value))
                {
                    assertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            lowerNonRecoverableGoingLow);
                    deassertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            lowerNonRecoverableGoingHigh);
                }
            }
        }
    }
    return ipmi::responseSuccess(enabled, assertionEnabledLsb,
                                 assertionEnabledMsb, deassertionEnabledLsb,
                                 deassertionEnabledMsb);
}

/** @brief implements the get Sensor event status command
 *  @param sensorNumber - sensor number, FFh = reserved
 *
 *  @returns IPMI completion code plus response data
 *   - sensorEventStatus - Sensor Event messages state
 *   - assertions        - Assertion event messages
 *   - deassertions      - Deassertion event messages
 */
ipmi::RspType<uint8_t,         // sensorEventStatus
              std::bitset<16>, // assertions
              std::bitset<16>  // deassertion
              >
    ipmiSenGetSensorEventStatus(ipmi::Context::ptr ctx, uint8_t sensorNum)
{
    if (sensorNum == reservedSensorNumber)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::string connection;
    std::string path;
    auto status = getSensorConnection(ctx, sensorNum, connection, path);
    if (status)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSenGetSensorEventStatus: Sensor connection Error",
            phosphor::logging::entry("SENSOR=%d", sensorNum));
        return ipmi::response(status);
    }
#ifdef FEATURE_HYBRID_SENSORS
    if (auto sensor = findStaticSensor(path);
        sensor != ipmi::sensor::sensors.end() &&
        getSensorEventTypeFromPath(path) !=
            static_cast<uint8_t>(SensorEventTypeCodes::threshold))
    {
        auto response = ipmi::sensor::get::mapDbusToAssertion(
            sensor->second, path, sensor->second.sensorInterface);
        std::bitset<16> assertions;
        // deassertions are not used.
        std::bitset<16> deassertions = 0;
        uint8_t sensorEventStatus;
        if (response.readingOrStateUnavailable)
        {
            sensorEventStatus |= static_cast<uint8_t>(
                IPMISensorReadingByte2::readingStateUnavailable);
        }
        if (response.scanningEnabled)
        {
            sensorEventStatus |= static_cast<uint8_t>(
                IPMISensorReadingByte2::sensorScanningEnable);
        }
        if (response.allEventMessagesEnabled)
        {
            sensorEventStatus |= static_cast<uint8_t>(
                IPMISensorReadingByte2::eventMessagesEnable);
        }
        assertions |= response.discreteReadingSensorStates << 8;
        assertions |= response.thresholdLevelsStates;
        return ipmi::responseSuccess(sensorEventStatus, assertions,
                                     deassertions);
    }
#endif

    SensorMap sensorMap;
    if (!getSensorMap(ctx->yield, connection, path, sensorMap))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSenGetSensorEventStatus: Sensor Mapping Error",
            phosphor::logging::entry("SENSOR=%s", path.c_str()));
        return ipmi::responseResponseError();
    }

    uint8_t sensorEventStatus =
        static_cast<uint8_t>(IPMISensorEventEnableByte2::sensorScanningEnable);
    std::bitset<16> assertions = 0;
    std::bitset<16> deassertions = 0;

    auto warningInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    auto criticalInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
    auto nonRecoverableInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.NonRecoverable");

    std::optional<bool> criticalDeassertHigh =
        thresholdDeassertMap[path]["CriticalAlarmHigh"];
    std::optional<bool> criticalDeassertLow =
        thresholdDeassertMap[path]["CriticalAlarmLow"];
    std::optional<bool> warningDeassertHigh =
        thresholdDeassertMap[path]["WarningAlarmHigh"];
    std::optional<bool> warningDeassertLow =
        thresholdDeassertMap[path]["WarningAlarmLow"];
    std::optional<bool> nonRecoverableDeassertHigh =
        thresholdDeassertMap[path]["NonRecoverableAlarmHigh"];
    std::optional<bool> nonRecoverableDeassertLow =
        thresholdDeassertMap[path]["NonRecoverableAlarmLow"];

    if (criticalDeassertHigh && !*criticalDeassertHigh)
    {
        deassertions.set(static_cast<size_t>(
            IPMIGetSensorEventEnableThresholds::upperCriticalGoingHigh));
    }
    if (criticalDeassertLow && !*criticalDeassertLow)
    {
        deassertions.set(static_cast<size_t>(
            IPMIGetSensorEventEnableThresholds::upperCriticalGoingLow));
    }
    if (warningDeassertHigh && !*warningDeassertHigh)
    {
        deassertions.set(static_cast<size_t>(
            IPMIGetSensorEventEnableThresholds::upperNonCriticalGoingHigh));
    }
    if (warningDeassertLow && !*warningDeassertLow)
    {
        deassertions.set(static_cast<size_t>(
            IPMIGetSensorEventEnableThresholds::lowerNonCriticalGoingHigh));
    }
    if (nonRecoverableDeassertHigh && !*nonRecoverableDeassertHigh)
    {
        deassertions.set(static_cast<size_t>(
            IPMIGetSensorEventEnableThresholds::upperNonRecoverableGoingHigh));
    }
    if (nonRecoverableDeassertLow && !*nonRecoverableDeassertLow)
    {
        deassertions.set(static_cast<size_t>(
            IPMIGetSensorEventEnableThresholds::lowerNonRecoverableGoingHigh));
    }
    if ((warningInterface != sensorMap.end()) ||
        (criticalInterface != sensorMap.end()) ||
        (nonRecoverableInterface != sensorMap.end()))
    {
        sensorEventStatus = static_cast<size_t>(
            IPMISensorEventEnableByte2::eventMessagesEnable);
        if (warningInterface != sensorMap.end())
        {
            auto& warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningAlarmHigh");
            auto warningLow = warningMap.find("WarningAlarmLow");
            auto warningHighAlarm = false;
            auto warningLowAlarm = false;

            if (warningHigh != warningMap.end())
            {
                warningHighAlarm = std::get<bool>(warningHigh->second);
            }
            if (warningLow != warningMap.end())
            {
                warningLowAlarm = std::get<bool>(warningLow->second);
            }
            if (warningHighAlarm)
            {
                assertions.set(static_cast<size_t>(
                    IPMIGetSensorEventEnableThresholds::
                        upperNonCriticalGoingHigh));
            }
            if (warningLowAlarm)
            {
                assertions.set(static_cast<size_t>(
                    IPMIGetSensorEventEnableThresholds::
                        lowerNonCriticalGoingLow));
            }
        }
        if (criticalInterface != sensorMap.end())
        {
            auto& criticalMap = criticalInterface->second;

            auto criticalHigh = criticalMap.find("CriticalAlarmHigh");
            auto criticalLow = criticalMap.find("CriticalAlarmLow");
            auto criticalHighAlarm = false;
            auto criticalLowAlarm = false;

            if (criticalHigh != criticalMap.end())
            {
                criticalHighAlarm = std::get<bool>(criticalHigh->second);
            }
            if (criticalLow != criticalMap.end())
            {
                criticalLowAlarm = std::get<bool>(criticalLow->second);
            }
            if (criticalHighAlarm)
            {
                assertions.set(static_cast<size_t>(
                    IPMIGetSensorEventEnableThresholds::
                        upperCriticalGoingHigh));
            }
            if (criticalLowAlarm)
            {
                assertions.set(static_cast<size_t>(
                    IPMIGetSensorEventEnableThresholds::lowerCriticalGoingLow));
            }
        }
        if (nonRecoverableInterface != sensorMap.end())
        {
            auto& nonRecoverableMap = nonRecoverableInterface->second;

            auto nonRecoverableHigh =
                nonRecoverableMap.find("NonRecoverableAlarmHigh");
            auto nonRecoverableLow =
                nonRecoverableMap.find("NonRecoverableAlarmLow");
            auto nonRecoverableHighAlarm = false;
            auto nonRecoverableLowAlarm = false;

            if (nonRecoverableHigh != nonRecoverableMap.end())
            {
                nonRecoverableHighAlarm =
                    std::get<bool>(nonRecoverableHigh->second);
            }
            if (nonRecoverableLow != nonRecoverableMap.end())
            {
                nonRecoverableLowAlarm =
                    std::get<bool>(nonRecoverableLow->second);
            }
            if (nonRecoverableHighAlarm)
            {
                assertions.set(static_cast<size_t>(
                    IPMIGetSensorEventEnableThresholds::
                        upperNonRecoverableGoingHigh));
            }
            if (nonRecoverableLowAlarm)
            {
                assertions.set(static_cast<size_t>(
                    IPMIGetSensorEventEnableThresholds::
                        lowerNonRecoverableGoingLow));
            }
        }
    }
    return ipmi::responseSuccess(sensorEventStatus, assertions, deassertions);
}

// Construct a type 1 SDR for threshold sensor.
void constructSensorSdrHeaderKey(uint16_t sensorNum, uint16_t recordID,
                                 get_sdr::SensorDataFullRecord& record)
{
    get_sdr::header::set_record_id(
        recordID, reinterpret_cast<get_sdr::SensorDataRecordHeader*>(&record));

    uint8_t sensornumber = static_cast<uint8_t>(sensorNum);
    uint8_t lun = static_cast<uint8_t>(sensorNum >> 8);

    record.header.sdr_version = ipmiSdrVersion;
    record.header.record_type = get_sdr::SENSOR_DATA_FULL_RECORD;
    record.header.record_length = sizeof(get_sdr::SensorDataFullRecord) -
                                  sizeof(get_sdr::SensorDataRecordHeader);
    record.key.owner_id = bmcI2CAddr;
    record.key.owner_lun = lun;
    record.key.sensor_number = sensornumber;
}

bool constructSensorSdr(
    ipmi::Context::ptr ctx,
    const std::unordered_set<std::string>& ipmiDecoratorPaths,
    uint16_t sensorNum, uint16_t recordID, const std::string& service,
    const std::string& path, get_sdr::SensorDataFullRecord& record)
{
    constructSensorSdrHeaderKey(sensorNum, recordID, record);

    SensorMap sensorMap;
    if (!getSensorMap(ctx->yield, service, path, sensorMap,
                      sensorMapSdrUpdatePeriod))
    {
        if constexpr (debug)
        {
            lg2::error("Failed to update sensor map for threshold sensor, "
                       "service: {SERVICE}, path: {PATH}",
                       "SERVICE", service, "PATH", path);
        }
        return false;
    }
    record.body.sensor_capabilities = 0x68; // auto rearm - todo hysteresis
    record.body.sensor_type = getSensorTypeFromPath(path);
    std::string type = getSensorTypeStringFromPath(path);
    for (const auto& [unitsType, units] : sensorUnits)
    {
        if (type == unitsType)
        {
            record.body.sensor_units_2_base = static_cast<uint8_t>(units);
        }
    }

    record.body.event_reading_type = getSensorEventTypeFromPath(path);

    auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");
    if (sensorObject == sensorMap.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getSensorDataRecord: sensorObject error");
        return GENERAL_ERROR;
    }
    uint8_t entityId = 0;
    uint8_t entityInstance = 0x01;

    // follow the association chain to get the parent board's entityid and
    // entityInstance
    updateIpmiFromAssociation(path, ipmiDecoratorPaths, sensorMap, entityId,
                              entityInstance);

    record.body.entity_id = entityId;
    record.body.entity_instance = entityInstance;

    double max = 0;
    double min = 0;
    getSensorMaxMin(sensorMap, max, min);

    int16_t mValue = 0;
    int8_t rExp = 0;
    int16_t bValue = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
    {
        lg2::error("constructSensorSdr: getSensorAttributes error");
        return false;
    }

    // The record.body is a struct SensorDataFullRecordBody
    // from sensorhandler.hpp in phosphor-ipmi-host.
    // The meaning of these bits appears to come from
    // table 43.1 of the IPMI spec.
    // The above 5 sensor attributes are stuffed in as follows:
    // Byte 21 = AA000000 = analog interpretation, 10 signed, 00 unsigned
    // Byte 22-24 are for other purposes
    // Byte 25 = MMMMMMMM = LSB of M
    // Byte 26 = MMTTTTTT = MSB of M (signed), and Tolerance
    // Byte 27 = BBBBBBBB = LSB of B
    // Byte 28 = BBAAAAAA = MSB of B (signed), and LSB of Accuracy
    // Byte 29 = AAAAEE00 = MSB of Accuracy, exponent of Accuracy
    // Byte 30 = RRRRBBBB = rExp (signed), bExp (signed)

    // apply M, B, and exponents, M and B are 10 bit values, exponents are 4

    record.body.m_lsb = mValue & 0xFF;

    uint8_t mBitSign = (mValue < 0) ? 1 : 0;
    uint8_t mBitNine = (mValue & 0x0100) >> 8;

    // move the smallest bit of the MSB into place (bit 9)
    // the MSbs are bits 7:8 in m_msb_and_tolerance
    record.body.m_msb_and_tolerance = (mBitSign << 7) | (mBitNine << 6);

    record.body.b_lsb = bValue & 0xFF;

    uint8_t bBitSign = (bValue < 0) ? 1 : 0;
    uint8_t bBitNine = (bValue & 0x0100) >> 8;

    // move the smallest bit of the MSB into place (bit 9)
    // the MSbs are bits 7:8 in b_msb_and_accuracy_lsb
    record.body.b_msb_and_accuracy_lsb = (bBitSign << 7) | (bBitNine << 6);

    uint8_t rExpSign = (rExp < 0) ? 1 : 0;
    uint8_t rExpBits = rExp & 0x07;

    uint8_t bExpSign = (bExp < 0) ? 1 : 0;
    uint8_t bExpBits = bExp & 0x07;

    // move rExp and bExp into place
    record.body.r_b_exponents =
        (rExpSign << 7) | (rExpBits << 4) | (bExpSign << 3) | bExpBits;

    // Set the analog reading byte interpretation accordingly
    record.body.sensor_units_1 = (bSigned ? 1 : 0) << 7;

    // TODO(): Perhaps care about Tolerance, Accuracy, and so on
    // These seem redundant, but derivable from the above 5 attributes
    // Original comment said "todo fill out rest of units"

    // populate sensor name from path
    std::string name;
    size_t nameStart = path.rfind("/");
    if (nameStart != std::string::npos)
    {
        name = path.substr(nameStart + 1, std::string::npos - nameStart);
    }

    std::replace(name.begin(), name.end(), '_', ' ');
    if (name.size() > FULL_RECORD_ID_STR_MAX_LENGTH)
    {
        // try to not truncate by replacing common words
        constexpr std::array<std::pair<const char*, const char*>, 2>
            replaceWords = {std::make_pair("Output", "Out"),
                            std::make_pair("Input", "In")};
        for (const auto& [find, replace] : replaceWords)
        {
            boost::replace_all(name, find, replace);
        }

        name.resize(FULL_RECORD_ID_STR_MAX_LENGTH);
    }
    get_sdr::body::set_id_strlen(name.size(), &record.body);
    get_sdr::body::set_id_type(3, &record.body); // "8-bit ASCII + Latin 1"
    std::strncpy(record.body.id_string, name.c_str(),
                 sizeof(record.body.id_string));

    // Remember the sensor name, as determined for this sensor number
    details::sdrStatsTable.updateName(sensorNum, name);
    IPMIThresholds thresholdData;
    try
    {
        thresholdData = getIPMIThresholds(sensorMap);
    }
    catch (const std::exception&)
    {
        lg2::error("constructSensorSdr: getIPMIThresholds error");
        return false;
    }

    if (thresholdData.criticalHigh)
    {
        record.body.upper_critical_threshold = *thresholdData.criticalHigh;
        record.body.supported_deassertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::criticalThreshold);
        record.body.supported_deassertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperCriticalGoingHigh);
        record.body.supported_assertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperCriticalGoingHigh);
        record.body.discrete_reading_setting_mask[0] |=
            static_cast<uint8_t>(IPMISensorReadingByte3::upperCritical);
    }
    if (thresholdData.warningHigh)
    {
        record.body.upper_noncritical_threshold = *thresholdData.warningHigh;
        record.body.supported_deassertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::nonCriticalThreshold);
        record.body.supported_deassertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperNonCriticalGoingHigh);
        record.body.supported_assertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperNonCriticalGoingHigh);
        record.body.discrete_reading_setting_mask[0] |=
            static_cast<uint8_t>(IPMISensorReadingByte3::upperNonCritical);
    }
    if (thresholdData.criticalLow)
    {
        record.body.lower_critical_threshold = *thresholdData.criticalLow;
        record.body.supported_assertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::criticalThreshold);
        record.body.supported_deassertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::lowerCriticalGoingLow);
        record.body.supported_assertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::lowerCriticalGoingLow);
        record.body.discrete_reading_setting_mask[0] |=
            static_cast<uint8_t>(IPMISensorReadingByte3::lowerCritical);
    }
    if (thresholdData.warningLow)
    {
        record.body.lower_noncritical_threshold = *thresholdData.warningLow;
        record.body.supported_assertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::nonCriticalThreshold);
        record.body.supported_deassertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::lowerNonCriticalGoingLow);
        record.body.supported_assertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::lowerNonCriticalGoingLow);
        record.body.discrete_reading_setting_mask[0] |=
            static_cast<uint8_t>(IPMISensorReadingByte3::lowerNonCritical);
    }

    // everything that is readable is setable
    record.body.discrete_reading_setting_mask[1] =
        record.body.discrete_reading_setting_mask[0];

    return true;
}

uint16_t getNumberOfSensors(void)
{
    return std::min(getSensorTree().size(), maxIPMISensors);
}

static int getSensorDataRecord(
    ipmi::Context::ptr ctx,
    const std::unordered_set<std::string>& ipmiDecoratorPaths,
    std::vector<uint8_t>& recordData, uint16_t recordID,
    [[maybe_unused]] uint8_t readBytes = std::numeric_limits<uint8_t>::max())

{
    recordData.clear();
    size_t lastRecord = ipmi::getNumberOfSensors() +
                        ipmi::sensor::getOtherSensorsCount(ctx) - 1;
    uint16_t nextRecord(recordID + 1);
    if (recordID == lastRecordIndex)
    {
        recordID = lastRecord;
    }
    if (recordID == lastRecord)
    {
        nextRecord = lastRecordIndex;
    }
    if (recordID > lastRecord)
    {
        // Disabling this log to reduce unnecessary error messages in the
        // journal. Enable if Debugging is Required
        /*phosphor::logging::log<phosphor::logging::level::ERR>(
            "getSensorDataRecord: recordID > lastRecord error"); */
        return GENERAL_ERROR;
    }
    if (recordID >= ipmi::getNumberOfSensors())
    {
        if (auto err = ipmi::sensor::getOtherSensorsDataRecord(ctx, recordID,
                                                               recordData);
            err < 0)
        {
            return lastRecordIndex;
        }
        return nextRecord;
    }

    // Perform a incremental scan of the SDR Record ID's and translate the
    // first 765 SDR records (i.e. maxIPMISensors) into IPMI Sensor
    // Numbers. The IPMI sensor numbers are not linear, and have a reserved
    // gap at 0xff. This code creates 254 sensors per LUN, excepting LUN 2
    // which has special meaning.
    std::string connection;
    std::string path;
    std::vector<std::string> interfaces;
    uint16_t sensNumFromRecID{recordID};
    if ((recordID > lun0MaxSensorNum) && (recordID < lun1MaxSensorNum))
    {
        // LUN 0 has one reserved sensor number. Compensate here by adding one
        // to the record ID
        sensNumFromRecID = recordID + 1;
        ctx->lun = 1;
    }
    else if ((recordID >= lun1MaxSensorNum) && (recordID < maxIPMISensors))
    {
        // LUN 0, 1 have a reserved sensor number. Compensate here by adding 2
        // to the record ID. Skip all 256 sensors in LUN 2, as it has special
        // rules governing its use.
        sensNumFromRecID = recordID + (maxSensorsPerLUN + 1) + 2;
        ctx->lun = 3;
    }

    auto status =
        getSensorConnection(ctx, static_cast<uint8_t>(sensNumFromRecID),
                            connection, path, &interfaces);

    if (status)
    {
        if constexpr (debug)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "getSensorDataRecord: getSensorConnection error");
        }
        return GENERAL_ERROR;
    }
    uint16_t sensorNum = getSensorNumberFromPath(path);
    // Return an error on LUN 2 assingments, and any sensor number beyond the
    // range of LUN 3
    if (((sensorNum > lun1MaxSensorNum) && (sensorNum <= maxIPMISensors)) ||
        (sensorNum > lun3MaxSensorNum))
    {
        if constexpr (debug)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "getSensorDataRecord: invalidSensorNumber");
        }
        return GENERAL_ERROR;
    }
    uint8_t sensornumber = static_cast<uint8_t>(sensorNum);
    uint8_t lun = static_cast<uint8_t>(sensorNum >> 8);

    if ((sensornumber != static_cast<uint8_t>(sensNumFromRecID)) &&
        (lun != ctx->lun))
    {
        if constexpr (debug)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "getSensorDataRecord: sensor record mismatch");
        }
        return GENERAL_ERROR;
    }
    // Construct full record (SDR type 1) for the threshold sensors
    if (std::find(interfaces.begin(), interfaces.end(),
                  sensor::sensorInterface) != interfaces.end())
    {
        get_sdr::SensorDataFullRecord record = {};

        // If the request doesn't read SDR body, construct only header and key
        // part to avoid additional DBus transaction.
        if (readBytes <= sizeof(record.header) + sizeof(record.key))
        {
            constructSensorSdrHeaderKey(sensorNum, recordID, record);
        }
        else if (!constructSensorSdr(ctx, ipmiDecoratorPaths, sensorNum,
                                     recordID, connection, path, record))
        {
            return GENERAL_ERROR;
        }
        recordData.insert(recordData.end(), reinterpret_cast<uint8_t*>(&record),
                          reinterpret_cast<uint8_t*>(&record) + sizeof(record));
        return nextRecord;
    }
    // handle discrete senosrs
    if (std::find(interfaces.begin(), interfaces.end(),
                  sensor::discreteInterface) != interfaces.end())
    {
        get_sdr::SensorDataCompactRecord record = {};
        std::unordered_set<std::string> ipmiDecoratorPaths;
        if (!constructDiscreteSdr(ctx, sensorNum, recordID, connection, path,
                                  ipmiDecoratorPaths, record))
        {
            return GENERAL_ERROR;
        }
        recordData.insert(recordData.end(), (uint8_t*)&record,
                          ((uint8_t*)&record) + sizeof(record));
    }
    return nextRecord;
}

/** @brief implements the get SDR Info command
 *  @param count - Operation
 *
 *  @returns IPMI completion code plus response data
 *   - sdrCount - sensor/SDR count
 *   - lunsAndDynamicPopulation - static/Dynamic sensor population flag
 */
static ipmi::RspType<uint8_t, // respcount
                     uint8_t, // dynamic population flags
                     uint32_t // last time a sensor was added
                     >
    ipmiSensorGetDeviceSdrInfo(ipmi::Context::ptr ctx,
                               std::optional<uint8_t> operation)
{
    auto& sensorTree{getSensorTree()};
    uint8_t sdrCount{};
    // Sensors are dynamically allocated
    uint8_t lunsAndDynamicPopulation{0x80};
    constexpr uint8_t getSdrCount{1};
    constexpr uint8_t getSensorCount{0};
    if (!getSensorSubtree(sensorTree) || sensorTree.empty())
    {
        return ipmi::responseResponseError();
    }
    uint16_t numSensors = getNumberOfSensors();
    if (operation.value_or(0) == getSdrCount)
    {
        sdrCount = numSensors + ipmi::sensor::getOtherSensorsCount(ctx) - 1;
    }
    // Count the number of Type 1 SDR entries assigned to the LUN
    else if (operation.value_or(0) == getSensorCount)
    {
        // Return the number of sensors attached to the LUN
        if ((ctx->lun == 0) && (numSensors > 0))
        {
            sdrCount =
                (numSensors > maxSensorsPerLUN) ? maxSensorsPerLUN : numSensors;
        }
        else if ((ctx->lun == 1) && (numSensors > maxSensorsPerLUN))
        {
            sdrCount = (numSensors > (2 * maxSensorsPerLUN))
                           ? maxSensorsPerLUN
                           : (numSensors - maxSensorsPerLUN) & maxSensorsPerLUN;
        }
        else if (ctx->lun == 3)
        {
            if (numSensors <= maxIPMISensors)
            {
                sdrCount = (numSensors - (2 * maxSensorsPerLUN)) &
                           maxSensorsPerLUN;
            }
            else
            {
                throw std::out_of_range(
                    "Maximum number of IPMI sensors exceeded.");
            }
        }
    }
    else
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // Get Sensor count. This returns the number of sensors
    if (numSensors > 0)
    {
        lunsAndDynamicPopulation |= 1;
    }
    if (numSensors > maxSensorsPerLUN)
    {
        lunsAndDynamicPopulation |= 2;
    }
    if (numSensors >= (maxSensorsPerLUN * 2))
    {
        lunsAndDynamicPopulation |= 8;
    }
    if (numSensors > maxIPMISensors)
    {
        // error
        throw std::out_of_range("Maximum number of IPMI sensors exceeded.");
    }
    return ipmi::responseSuccess(sdrCount, lunsAndDynamicPopulation,
                                 sdrLastAdd);
}

/*
<uint8_t, uint8_t, uint8_t> <Action Supported, ,No of Event
Filtering-Table-Entries>
*/
ipmi::RspType<uint8_t, uint8_t, uint8_t> ipmiSenGetPefCapabilities()
{
    uint8_t pefVersion = 0;
    uint8_t pefactionSupported = 0;
    uint8_t eveFltTblEntiesCount = 0;

    PropertyMap pefCfgValues;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    auto method =
        dbus->new_method_call(pefBus, pefObj, PROP_INTF, METHOD_GET_ALL);
    method.append(pefConfInfoIntf);
    auto reply = dbus->call(method);
    if (reply.is_method_error())
    {
        lg2::error("Failed to get all Event Filtering properties");
    }
    try
    {
        reply.read(pefCfgValues);
    }
    catch (const std::exception&)
    {
        return ipmi::responseResponseError();
    }

    static constexpr auto pefver = "Version";
    static constexpr auto actionSupported = "ActionSupported";
    static constexpr auto maxTblEntry = "MaxEventTblEntry";

    auto iterId = pefCfgValues.find(pefver);
    if (iterId == pefCfgValues.end())
    {
        lg2::error("Failed to get PEF Version");
    }
    pefVersion = static_cast<uint8_t>(std::get<uint8_t>(iterId->second));

    iterId = pefCfgValues.find(actionSupported);
    if (iterId == pefCfgValues.end())
    {
        lg2::error("Failed to get ActionSupported Value");
    }
    pefactionSupported =
        static_cast<uint8_t>(std::get<uint8_t>(iterId->second));

    iterId = pefCfgValues.find(maxTblEntry);
    if (iterId == pefCfgValues.end())
    {
        lg2::error("Failed to get EventTable Entries Value");
    }
    eveFltTblEntiesCount =
        static_cast<uint8_t>(std::get<uint8_t>(iterId->second));

    return ipmi::responseSuccess(pefVersion, pefactionSupported,
                                 eveFltTblEntiesCount);
}

ipmi::RspType<uint8_t> // Present Timer Countdown Value
    ipmiSenArmPEFpostponeTimer(uint8_t pefPostponeTimer)
{
    uint8_t countdownTmrValue;

    static constexpr auto countdownValue = "TmrCountdownValue";
    // Set the Value to DBUS
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        ipmi::setDbusProperty(*dbus, pefBus, pefPostponeTmrObj,
                              pefPostponeTmrIface, "ArmPEFPostponeTmr",
                              pefPostponeTimer);
    }

    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Failed to update Timer Value");
        return ipmi::responseUnspecifiedError();
    }

    // Get the value of PefPostpone timer in DBUS
    PropertyMap pefCfgValues;
    // sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    auto method = dbus->new_method_call(pefBus, pefPostponeTmrObj, PROP_INTF,
                                        METHOD_GET_ALL);
    method.append(pefPostponeCountDownIface);
    auto reply = dbus->call(method);
    if (reply.is_method_error())
    {
        lg2::error("Failed to get Countdown property");
    }
    try
    {
        reply.read(pefCfgValues);
    }
    catch (const std::exception&)
    {
        return ipmi::responseResponseError();
    }

    auto iterId = pefCfgValues.find(countdownValue);
    if (iterId == pefCfgValues.end())
    {
        lg2::error("Failed to get PEF Version");
    }
    countdownTmrValue = static_cast<uint8_t>(std::get<uint8_t>(iterId->second));

    // Checking Conditions as per the ipmi Specification
    if (pefPostponeTimer == pefDisable)
    {
        lg2::info("Postpone Timer is Disabled");
    }
    else if ((pefPostponeTimer != tempPefDisable) &&
             (pefPostponeTimer != pefDisable) &&
             (pefPostponeTimer != presentCwnValue))
    {
        lg2::info(
            "PEF Task is Disabled by Postpone Timer and Starting Countdown Timer Value ");
        return ipmi::responseSuccess(pefPostponeTimer);
    }
    else if (pefPostponeTimer == tempPefDisable)
    {
        lg2::info("PEF Task is Disabled by Postpone Timer");
        return ipmi::responseSuccess(pefPostponeTimer);
    }
    else if ((pefPostponeTimer == presentCwnValue))
    {
        lg2::info("Get the Current Countdown Value");
    }

    return ipmi::responseSuccess(countdownTmrValue);
}

ipmi::RspType<uint8_t,             // ParameterVersion
              std::vector<uint8_t> // ParamData
              >
    ipmiPefGetConfParamCmd([[maybe_unused]] ipmi::Context::ptr ctx,
                           uint8_t ParamSelector, uint8_t setSelector,
                           uint8_t blockSelector)
{
    uint8_t paraVer = 0;
    uint8_t paraData = 0;
    uint8_t setSel = 0;
    std::vector<uint8_t> paraDataByte{};
    paraVer = ipmiPefParamVer;
    setSel = setSelector;
    if (((ParamSelector >> 7) & eventData1) == eventData1)
    {
        return ipmi::responseSuccess(paraVer, paraDataByte);
    }

    ParamSelector = ParamSelector & enableFilter;
    switch (PEFConfParam(ParamSelector))
    {
        case PEFConfParam::setInProgress:
        {
            if ((setSelector != 0) || (blockSelector != 0))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            paraData = pefSetInPro;
            paraDataByte.push_back(paraData);
            break;
        }

        case PEFConfParam::pefControl:
        {
            if ((setSelector != 0) || (blockSelector != 0))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            try
            {
                Value variant = ipmi::getDbusProperty(
                    *dbus, pefBus, pefObj, pefConfInfoIntf, "PEFControl");
                paraData = std::get<uint8_t>(variant);
                paraDataByte.push_back(paraData);
            }
            catch (std::exception& e)
            {
                lg2::error("Failed to get PEFControl property: {ERROR}",
                           "ERROR", e);
                return ipmi::responseUnspecifiedError();
            }
            break;
        }
        case PEFConfParam::pefActionGlobalControl:
        {
            if ((setSelector != 0) || (blockSelector != 0))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            try
            {
                Value variant = ipmi::getDbusProperty(
                    *dbus, pefBus, pefObj, pefConfInfoIntf,
                    "PEFActionGblControl");
                paraData = std::get<uint8_t>(variant);
                paraDataByte.push_back(paraData);
            }
            catch (std::exception& e)
            {
                lg2::error(
                    "Failed to get PEFActionGblControl property: {ERROR}",
                    "ERROR", e);
                return ipmi::responseUnspecifiedError();
            }
            break;
        }
        case PEFConfParam::pefStartupDelay:
        {
            if ((setSelector != 0) || (blockSelector != 0))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            try
            {
                Value variant = ipmi::getDbusProperty(
                    *dbus, pefBus, pefObj, pefConfInfoIntf, "PEFStartupDly");
                paraData = std::get<uint8_t>(variant);
                paraDataByte.push_back(paraData);
            }
            catch (std::exception& e)
            {
                lg2::error("Failed to get PEFStartupDly property : {ERROR}",
                           "ERROR", e);
                return ipmi::responseUnspecifiedError();
            }
            break;
        }
        case PEFConfParam::pefAlertStartupDelay:
        {
            if ((setSelector != 0) || (blockSelector != 0))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            try
            {
                Value variant = ipmi::getDbusProperty(
                    *dbus, pefBus, pefObj, pefConfInfoIntf,
                    "PEFAlertStartupDly");
                paraData = std::get<uint8_t>(variant);
                paraDataByte.push_back(paraData);
            }
            catch (std::exception& e)
            {
                lg2::error(
                    "Failed to get PEFAlertStartupDly property : {ERROR}",
                    "ERROR", e);
                return ipmi::responseUnspecifiedError();
            }
            break;
        }
        case PEFConfParam::numEventFilter:
        {
            if ((setSelector != 0) || (blockSelector != 0))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            paraData = maxEventTblEntry;
            paraDataByte.push_back(paraData);
            break;
        }
        case PEFConfParam::eventFilterTable:
        {
            if (setSel == eventData0)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            if (setSel > maxEventTblEntry)
            {
                return ipmi::responseParmOutOfRange();
            }
            uint8_t offsetMask1 = 0, offsetMask2 = 0;
            uint16_t eveData1OffsetMask;
            std::string pefEveObjEntry =
                eventFilterTableObj + std::to_string(setSel);
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            try
            {
                ipmi::PropertyMap result = ipmi::getAllDbusProperties(
                    *dbus, pefBus, pefEveObjEntry, eventFilterTableIntf);
                paraDataByte.push_back(setSel);
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("FilterConfig")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("EvtFilterAction")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("AlertPolicyNum")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("EventSeverity")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("GenIDByte1")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("GenIDByte2")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("SensorType")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("SensorNum")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("EventTrigger")));
                eveData1OffsetMask =
                    std::get<uint16_t>(result.at("EventData1OffsetMask"));
                offsetMask1 = ((eveData1OffsetMask >> 8) & 0xff);
                offsetMask2 = (eveData1OffsetMask & 0xff);
                paraDataByte.push_back(offsetMask1);
                paraDataByte.push_back(offsetMask2);
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("EventData1ANDMask")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("EventData1Cmp1")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("EventData1Cmp2")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("EventData2ANDMask")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("EventData2Cmp1")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("EventData2Cmp2")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("EventData3ANDMask")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("EventData3Cmp1")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("EventData3Cmp2")));
            }
            catch (std::exception& e)
            {
                lg2::error(
                    "Failed to get all eventFilter Entry property : {ERROR}",
                    "ERROR", e);
                return ipmi::responseUnspecifiedError();
            }
            break;
        }
        case PEFConfParam::eventFilterTableData1:
        {
            if (setSel == eventData0)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            if (setSel > maxEventTblEntry)
            {
                return ipmi::responseParmOutOfRange();
            }
            std::string pefEveObjEntry =
                eventFilterTableObj + std::to_string(setSel);
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            try
            {
                Value variant =
                    ipmi::getDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                          eventFilterTableIntf, "FilterConfig");
                paraData = std::get<uint8_t>(variant);
                paraDataByte.push_back(setSel);
                paraDataByte.push_back(paraData);
            }
            catch (std::exception& e)
            {
                lg2::error("Failed to get Filter config property : {ERROR}",
                           "ERROR", e);
                return ipmi::responseUnspecifiedError();
            }
            break;
        }
        case PEFConfParam::numAlertPolicyTable:
        {
            if ((setSelector != 0) || (blockSelector != 0))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            paraData = maxAlertPolicyEntry;
            paraDataByte.push_back(paraData);
            break;
        }
        case PEFConfParam::alertPolicyTable:
        {
            if (setSel == eventData0)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            if (setSel > maxAlertPolicyEntry)
            {
                return ipmi::responseParmOutOfRange();
            }
            std::string pefAlertObjEntry =
                alertPolicyTableObj + std::to_string(setSel);
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            try
            {
                ipmi::PropertyMap result = ipmi::getAllDbusProperties(
                    *dbus, pefBus, pefAlertObjEntry, alertPolicyTableIntf);
                paraDataByte.push_back(setSel);
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("AlertNum")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("ChannelDestSel")));
                paraDataByte.push_back(
                    std::get<uint8_t>(result.at("AlertStingkey")));
            }
            catch (std::exception& e)
            {
                lg2::error(
                    "Failed to get all AlertPolicy Entry property : {ERROR}",
                    "ERROR", e);
                return ipmi::responseUnspecifiedError();
            }
            break;
        }

        default:
            return response(ipmiCCParamNotSupported);
    }
    return ipmi::responseSuccess(paraVer, paraDataByte);
}

ipmi::RspType<> ipmiPefSetConfParamCmd(uint8_t ParamSelector,
                                       ipmi::message::Payload& payload)
{
    uint8_t paraData = 0;
    if (((ParamSelector >> 7) & eventData1) == eventData1)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    ParamSelector = ParamSelector & enableFilter;
    if ((ParamSelector == static_cast<uint8_t>(PEFConfParam::numEventFilter)) ||
        (ParamSelector ==
         static_cast<uint8_t>(PEFConfParam::numAlertPolicyTable)))
    {
        return response(ipmiCCParamReadOnly);
    }
    switch (PEFConfParam(ParamSelector))
    {
        case PEFConfParam::setInProgress:
        {
            uint8_t setComplete = 0x00;
            uint8_t setInProgress = 0x01;
            if (payload.unpack(paraData) || !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            if ((paraData != setComplete) && (paraData != setInProgress))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            pefSetInPro = paraData;
            break;
        }
        case PEFConfParam::pefControl:
        {
            if (payload.unpack(paraData) || !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            if ((paraData & pefControlValue))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            try
            {
                ipmi::setDbusProperty(*dbus, pefBus, pefObj, pefConfInfoIntf,
                                      "PEFControl", paraData);
            }
            catch (std::exception& e)
            {
                lg2::error("Failed to set PEFControl property : {ERROR}",
                           "ERROR", e);
                return ipmi::responseUnspecifiedError();
            }
            break;
        }
        case PEFConfParam::pefActionGlobalControl:
        {
            if (payload.unpack(paraData) || !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            if ((paraData & reserveBit1) || (paraData & reserveBit2))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            try
            {
                ipmi::setDbusProperty(*dbus, pefBus, pefObj, pefConfInfoIntf,
                                      "PEFActionGblControl", paraData);
            }
            catch (std::exception& e)
            {
                lg2::error(
                    "Failed to set PEFActionGblControl property : {ERROR}",
                    "ERROR", e);
                return ipmi::responseUnspecifiedError();
            }
            break;
        }
        case PEFConfParam::pefStartupDelay:
        {
            if (payload.unpack(paraData) || !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            try
            {
                ipmi::setDbusProperty(*dbus, pefBus, pefObj, pefConfInfoIntf,
                                      "PEFStartupDly", paraData);
            }
            catch (std::exception& e)
            {
                lg2::error("Failed to set PEFStartupDly property : {ERROR}",
                           "ERROR", e);
                return ipmi::responseUnspecifiedError();
            }
            break;
        }
        case PEFConfParam::pefAlertStartupDelay:
        {
            if (payload.unpack(paraData) || !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            try
            {
                ipmi::setDbusProperty(*dbus, pefBus, pefObj, pefConfInfoIntf,
                                      "PEFAlertStartupDly", paraData);
            }
            catch (std::exception& e)
            {
                lg2::error(
                    "Failed to set PEFAlertStartupDly property : {ERROR}",
                    "ERROR", e);
                return ipmi::responseUnspecifiedError();
            }
            break;
        }
        case PEFConfParam::eventFilterTable:
        {
            std::vector<uint8_t> entryData;
            uint16_t offsetMask = 0, tmpOffsetMask = 0;
            // uint8_t maxEventTblEntry = 0x40;
            uint8_t evenSevtmp;
            if (payload.unpack(entryData) || !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }

            if (entryData.size() > 21 || entryData.size() < 21)
            {
                return ipmi::responseReqDataLenInvalid();
            }

            if (entryData.at(0) == 0x00)
            {
                return ipmi::responseInvalidFieldRequest();
            }

            if (entryData.at(0) > maxEventTblEntry)
            {
                return ipmi::responseParmOutOfRange();
            }

            if (((entryData.at(1) & flterConfigRrve1) != 0) ||
                (((entryData.at(1) >> 5) & flterConfigRrve2) ==
                 flterConfigRrve2) ||
                (((entryData.at(1) >> 5) & eventData1) == eventData1))
            {
                return ipmi::responseInvalidFieldRequest();
            }

            if ((((entryData.at(2) >> 7) & eventData1) == eventData1) ||
                (((entryData.at(3) >> 7) & eventData1) == eventData1))
            {
                return ipmi::responseInvalidFieldRequest();
            }

            evenSevtmp = entryData.at(4);
            if ((((~evenSevtmp) + 1) & entryData.at(4)) != entryData.at(4))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            std::string pefEveObjEntry =
                eventFilterTableObj + std::to_string(entryData.at(0));
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            try
            {
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "FilterConfig",
                                      entryData.at(1));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "EvtFilterAction",
                                      entryData.at(2));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "AlertPolicyNum",
                                      entryData.at(3));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "EventSeverity",
                                      entryData.at(4));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "GenIDByte1",
                                      entryData.at(5));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "GenIDByte2",
                                      entryData.at(6));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "SensorType",
                                      entryData.at(7));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "SensorNum",
                                      entryData.at(8));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "EventTrigger",
                                      entryData.at(9));
                tmpOffsetMask = entryData.at(10);
                offsetMask = ((tmpOffsetMask << 8) | (entryData.at(11) & 0xff));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf,
                                      "EventData1OffsetMask", offsetMask);
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "EventData1ANDMask",
                                      entryData.at(12));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "EventData1Cmp1",
                                      entryData.at(13));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "EventData1Cmp2",
                                      entryData.at(14));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "EventData2ANDMask",
                                      entryData.at(15));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "EventData2Cmp1",
                                      entryData.at(16));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "EventData2Cmp2",
                                      entryData.at(17));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "EventData3ANDMask",
                                      entryData.at(18));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "EventData3Cmp1",
                                      entryData.at(19));
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "EventData3Cmp2",
                                      entryData.at(20));
            }
            catch (std::exception& e)
            {
                lg2::error("Failed to set Event filtering properties : {ERROR}",
                           "ERROR", e);
                return ipmi::responseUnspecifiedError();
            }
            break;
        }
        case PEFConfParam::eventFilterTableData1:
        {
            std::vector<uint8_t> entryData;
            if (payload.unpack(entryData) || !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            if (entryData.size() > 2 || entryData.size() < 2)
            {
                return ipmi::responseReqDataLenInvalid();
            }
            if (entryData.at(0) == 0x00)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            if (entryData.at(0) > maxEventTblEntry)
            {
                return ipmi::responseParmOutOfRange();
            }
            if (((entryData.at(1) & flterConfigRrve1) != 0) ||
                (((entryData.at(1) >> 5) & flterConfigRrve2) ==
                 flterConfigRrve2) ||
                (((entryData.at(1) >> 5) & eventData1) == eventData1))
            {
                return ipmi::responseInvalidFieldRequest();
            }

            std::string pefEveObjEntry =
                eventFilterTableObj + std::to_string(entryData.at(0));
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            try
            {
                ipmi::setDbusProperty(*dbus, pefBus, pefEveObjEntry,
                                      eventFilterTableIntf, "FilterConfig",
                                      entryData.at(1));
            }
            catch (std::exception& e)
            {
                lg2::error("Failed to set FilterConfig data : {ERROR}", "ERROR",
                           e);
                return ipmi::responseUnspecifiedError();
            }
            break;
        }
        case PEFConfParam::alertPolicyTable:
        {
            std::vector<uint8_t> entryData;
            // uint8_t NumAlertPolicyEntry = 0x07;
            if (payload.unpack(entryData) || !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            if (entryData.size() > 4 || entryData.size() < 4)
            {
                return ipmi::responseReqDataLenInvalid();
            }
            if ((entryData.at(0) == eventData0) ||
                ((entryData.at(0) & reserveBit1) == reserveBit1) ||
                ((entryData.at(1) & numAlertPolicyEntry) > 4) ||
                ((entryData.at(1) & pefControlValue) == 0))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            if (entryData.at(0) > maxAlertPolicyEntry)
            {
                return ipmi::responseParmOutOfRange();
            }

            std::string pefAlertObjEntry =
                alertPolicyTableObj + std::to_string(entryData.at(0));
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            try
            {
                ipmi::setDbusProperty(*dbus, pefBus, pefAlertObjEntry,
                                      alertPolicyTableIntf, "AlertNum",
                                      entryData.at(1));
                ipmi::setDbusProperty(*dbus, pefBus, pefAlertObjEntry,
                                      alertPolicyTableIntf, "ChannelDestSel",
                                      entryData.at(2));
                ipmi::setDbusProperty(*dbus, pefBus, pefAlertObjEntry,
                                      alertPolicyTableIntf, "AlertStingkey",
                                      entryData.at(3));
            }
            catch (std::exception& e)
            {
                lg2::error("Failed to set Alert Policy properties : {ERROR}",
                           "ERROR", e);
                return ipmi::responseUnspecifiedError();
            }
            break;
        }
        default:
            return response(ipmiCCParamNotSupported);
    }
    return ipmi::responseSuccess();
}

/* end sensor commands */

/* storage commands */

ipmi::RspType<uint8_t,  // sdr version
              uint16_t, // record count
              uint16_t, // free space
              uint32_t, // most recent addition
              uint32_t, // most recent erase
              uint8_t   // operationSupport
              >
    ipmiStorageGetSDRRepositoryInfo(ipmi::Context::ptr ctx)
{
    constexpr const uint16_t unspecifiedFreeSpace = 0xFFFF;
    uint16_t recordCount =
        ipmi::getNumberOfSensors() + ipmi::sensor::getOtherSensorsCount(ctx);

    uint8_t operationSupport = static_cast<uint8_t>(
        SdrRepositoryInfoOps::overflow); // write not supported

    operationSupport |=
        static_cast<uint8_t>(SdrRepositoryInfoOps::allocCommandSupported);
    operationSupport |= static_cast<uint8_t>(
        SdrRepositoryInfoOps::reserveSDRRepositoryCommandSupported);
    return ipmi::responseSuccess(ipmiSdrVersion, recordCount,
                                 unspecifiedFreeSpace, sdrLastAdd,
                                 sdrLastRemove, operationSupport);
}

/** @brief implements the get SDR allocation info command
 *
 *  @returns IPMI completion code plus response data
 *   - allocUnits    - Number of possible allocation units
 *   - allocUnitSize - Allocation unit size in bytes.
 *   - allocUnitFree - Number of free allocation units
 *   - allocUnitLargestFree - Largest free block in allocation units
 *   - maxRecordSize    - Maximum record size in allocation units.
 */
ipmi::RspType<uint16_t, // allocUnits
              uint16_t, // allocUnitSize
              uint16_t, // allocUnitFree
              uint16_t, // allocUnitLargestFree
              uint8_t   // maxRecordSize
              >
    ipmiStorageGetSDRAllocationInfo()
{
    // 0000h unspecified number of alloc units
    constexpr uint16_t allocUnits = 0;

    constexpr uint16_t allocUnitFree = 0;
    constexpr uint16_t allocUnitLargestFree = 0;
    // only allow one block at a time
    constexpr uint8_t maxRecordSize = 1;

    return ipmi::responseSuccess(allocUnits, maxSDRTotalSize, allocUnitFree,
                                 allocUnitLargestFree, maxRecordSize);
}

/** @brief implements the reserve SDR command
 *  @returns IPMI completion code plus response data
 *   - sdrReservationID
 */
ipmi::RspType<uint16_t> ipmiStorageReserveSDR()
{
    sdrReservationID++;
    if (sdrReservationID == 0)
    {
        sdrReservationID++;
    }

    return ipmi::responseSuccess(sdrReservationID);
}

ipmi::RspType<uint16_t,            // next record ID
              std::vector<uint8_t> // payload
              >
    ipmiStorageGetSDR(ipmi::Context::ptr ctx, uint16_t reservationID,
                      uint16_t recordID, uint8_t offset, uint8_t bytesToRead)
{
    // reservation required for partial reads with non zero offset into
    // record
    if ((sdrReservationID == 0 || reservationID != sdrReservationID) && offset)
    {
        if constexpr (debug)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiStorageGetSDR: responseInvalidReservationId");
        }
        return ipmi::responseInvalidReservationId();
    }
    auto& sensorTree = getSensorTree();
    if (!getSensorSubtree(sensorTree) && sensorTree.empty())
    {
        if constexpr (debug)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiStorageGetSDR: getSensorSubtree error");
        }
        return response(ccSensorInvalid);
    }
    auto& ipmiDecoratorPaths = getIpmiDecoratorPaths(ctx);

    std::vector<uint8_t> record;
    int nextRecordId = getSensorDataRecord(
        ctx, ipmiDecoratorPaths.value_or(std::unordered_set<std::string>()),
        record, recordID, offset + bytesToRead);

    if (nextRecordId < 0)
    {
        if constexpr (debug)
        {
            lg2::error("ipmiStorageGetSDR: fail to get SDR");
        }
        return ipmi::responseSensorInvalid();
    }

    get_sdr::SensorDataRecordHeader* hdr =
        reinterpret_cast<get_sdr::SensorDataRecordHeader*>(record.data());
    if (!hdr)
    {
        if constexpr (debug)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiStorageGetSDR: record header is null");
        }
        return ipmi::responseSuccess(nextRecordId, record);
    }

    size_t sdrLength =
        sizeof(get_sdr::SensorDataRecordHeader) + hdr->record_length;

    if (offset >= sdrLength)
    {
        if constexpr (debug)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiStorageGetSDR: offset is outside the record");
        }
        return ipmi::responseRetBytesUnavailable();
    }
    if (sdrLength < (offset + bytesToRead))
    {
        bytesToRead = sdrLength - offset;
    }

    uint8_t* respStart = reinterpret_cast<uint8_t*>(hdr) + offset;
    if (!respStart)
    {
        if constexpr (debug)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiStorageGetSDR: record is null");
        }
        return ipmi::responseSuccess(nextRecordId, record);
    }
    std::vector<uint8_t> recordData(respStart, respStart + bytesToRead);

    return ipmi::responseSuccess(nextRecordId, recordData);
}

// Get SDR Repository Time
ipmi::RspType<uint32_t> // current time
    ipmiStorageGetSDRRepositoryTime(ipmi::Context::ptr ctx)
{
    auto& sensorTree = getSensorTree();
    if (!getSensorSubtree(sensorTree) && sensorTree.empty())
    {
        return ipmi::responseResponseError();
    }

    size_t fruCount = 0;
    ipmi::Cc ret = ipmi::storage::getFruSdrCount(ctx, fruCount);
    if (ret != ipmi::ccSuccess)
    {
        return ipmi::response(ret);
    }

    return ipmi::responseSuccess(sdrLastUpdate);
}
/* end storage commands */

void registerSensorFunctions()
{
    // <Platform Event>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdPlatformEvent,
                          ipmi::Privilege::Operator, ipmiSenPlatformEvent);

    // <Get Sensor Type>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorType,
                          ipmi::Privilege::User, ipmiGetSensorTypeCmd);

    // <Get Sensor Reading>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorReading,
                          ipmi::Privilege::User, ipmiSenGetSensorReading);

    // <Get Sensor Threshold>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorThreshold,
                          ipmi::Privilege::User, ipmiSenGetSensorThresholds);

    // <Set Sensor Threshold>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdSetSensorThreshold,
                          ipmi::Privilege::Operator,
                          ipmiSenSetSensorThresholds);

    // <Get Sensor Event Enable>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorEventEnable,
                          ipmi::Privilege::User, ipmiSenGetSensorEventEnable);

    // <Get Sensor Event Status>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorEventStatus,
                          ipmi::Privilege::User, ipmiSenGetSensorEventStatus);

    // <PEF Get Capabilities>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetPefCapabilities,
                          ipmi::Privilege::User, ipmiSenGetPefCapabilities);

    // <Arm PEF Postpone Timer>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdArmPefPostponeTimer,
                          ipmi::Privilege::Admin, ipmiSenArmPEFpostponeTimer);

    //<Get PEF Configuration Parameter>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetPefConfigurationParams,
                          ipmi::Privilege::Operator, ipmiPefGetConfParamCmd);

    //<Set PEF Configuration Parameter>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdSetPefConfigurationParams,
                          ipmi::Privilege::Admin, ipmiPefSetConfParamCmd);

    // register all storage commands for both Sensor and Storage command
    // versions

    // <Get SDR Repository Info>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSdrRepositoryInfo,
                          ipmi::Privilege::User,
                          ipmiStorageGetSDRRepositoryInfo);

    // <Get Device SDR Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetDeviceSdrInfo,
                          ipmi::Privilege::sysIface,
                          ipmiSensorGetDeviceSdrInfo);

    // <Get SDR Allocation Info>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSdrRepositoryAllocInfo,
                          ipmi::Privilege::User,
                          ipmiStorageGetSDRAllocationInfo);

    // <Reserve SDR Repo>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdReserveDeviceSdrRepository,
                          ipmi::Privilege::sysIface, ipmiStorageReserveSDR);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnStorage,
                          ipmi::storage::cmdReserveSdrRepository,
                          ipmi::Privilege::User, ipmiStorageReserveSDR);

    // <Get Sdr>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetDeviceSdr,
                          ipmi::Privilege::sysIface, ipmiStorageGetSDR);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSdr, ipmi::Privilege::User,
                          ipmiStorageGetSDR);

    // <Get SDR Repository Time>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSdrRepositoryTime,
                          ipmi::Privilege::User,
                          ipmiStorageGetSDRRepositoryTime);
}
} // namespace ipmi

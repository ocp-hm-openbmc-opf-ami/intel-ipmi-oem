/*
// Copyright (c) 2017-2019 Intel Corporation
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

#include "storagecommands.hpp"

#include "commandutils.hpp"
#include "fruutils.hpp"
#include "ipmi_to_redfish_hooks.hpp"
#include "sdrutils.hpp"
#include "types.hpp"
#include "xyz/openbmc_project/Logging/Entry/server.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <ipmid/api.hpp>
#include <ipmid/message.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-ipmi-host/selutility.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/timer.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Logging/SEL/error.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unordered_set>

static constexpr bool DEBUG = false;

constexpr uint16_t InfoEventEntries = 2639;
constexpr uint16_t ErrorEventEntries = 1000;

using namespace phosphor::logging;
using namespace ami::ipmi::sel;
using ErrLevel = sdbusplus::xyz::openbmc_project::Logging::server::Entry::Level;
auto sevLevel = ErrLevel::Informational;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

using SELRecordID = uint16_t;
using SELEntry = ipmi::sel::SELEventRecordFormat;
using SELCacheMap = std::map<SELRecordID, SELEntry>;
using additionalDataMap = std::map<std::string, std::string>;
using entryDataMap = std::map<ipmi::sel::PropertyName, ipmi::sel::PropertyType>;

SELCacheMap selCacheMap __attribute__((init_priority(101)));
bool selCacheMapInitialized;
std::unique_ptr<sdbusplus::bus::match_t> selAddedMatch
    __attribute__((init_priority(101)));
std::unique_ptr<sdbusplus::bus::match_t> selRemovedMatch
    __attribute__((init_priority(101)));
std::unique_ptr<sdbusplus::bus::match_t> selUpdatedMatch
    __attribute__((init_priority(101)));

template <typename TP>
std::time_t to_time_t(TP tp)
{
    using namespace std::chrono;
    auto sctp = time_point_cast<system_clock::duration>(tp - TP::clock::now() +
                                                        system_clock::now());
    return system_clock::to_time_t(sctp);
}

static int getFileTimestamp(const std::filesystem::path& file)
{
    std::error_code ec;
    std::filesystem::file_time_type ftime =
        std::filesystem::last_write_time(file, ec);
    if (ec)
    {
        return ::ipmi::sel::invalidTimeStamp;
    }

    return to_time_t(ftime);
}

inline uint16_t getLoggingId(const std::string& p)
{
    namespace fs = std::filesystem;
    fs::path entryPath(p);
    return std::stoul(entryPath.filename().string());
}

std::string getLoggingObjPath(uint16_t id)
{
    return std::string(ipmi::sel::logBasePath) + "/" + std::to_string(id);
}

std::chrono::seconds getEntryTimeStamp(const std::string& objPath)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    auto service = ipmi::getService(bus, logEntryIntf, objPath);

    using namespace std::string_literals;
    static const auto propTimeStamp = "Timestamp"s;

    auto methodCall = bus.new_method_call(service.c_str(), objPath.c_str(),
                                          ipmi::sel::propIntf, "Get");
    methodCall.append(logEntryIntf);
    methodCall.append(propTimeStamp);

    auto reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in reading Timestamp from Entry interface");
        elog<InternalFailure>();
    }

    std::variant<uint64_t> timeStamp;
    reply.read(timeStamp);

    std::chrono::milliseconds chronoTimeStamp(std::get<uint64_t>(timeStamp));

    return std::chrono::duration_cast<std::chrono::seconds>(chronoTimeStamp);
}

void readLoggingObjectPathst(ipmi::sel::ObjectPaths& paths)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    auto depth = 0;
    paths.clear();

    auto mapperCall =
        bus.new_method_call(ipmi::sel::mapperBusName, ipmi::sel::mapperObjPath,
                            ipmi::sel::mapperIntf, "GetSubTreePaths");
    mapperCall.append(ipmi::sel::logBasePath);
    mapperCall.append(depth);
    mapperCall.append(ipmi::sel::ObjectPaths({ipmi::sel::logEntryIntf}));

    try
    {
        auto reply = bus.call(mapperCall);
        reply.read(paths);
    }
    catch (const sdbusplus::exception::exception& e)
    {
        if (strcmp(e.name(),
                   "xyz.openbmc_project.Common.Error.ResourceNotFound"))
        {
            throw;
        }
    }
    std::sort(paths.begin(), paths.end(),
              [](const std::string& a, const std::string& b) {
                  namespace fs = std::filesystem;
                  fs::path pathA(a);
                  fs::path pathB(b);
                  auto idA = std::stoul(pathA.filename().string());
                  auto idB = std::stoul(pathB.filename().string());

                  return idA < idB;
              });
}

std::pair<std::string, std::string> parseEntry(const std::string& entry)
{
    constexpr auto equalSign = "=";
    auto pos = entry.find(equalSign);
    assert(pos != std::string::npos);
    auto key = entry.substr(0, pos);
    auto val = entry.substr(pos + 1);
    return {key, val};
}
// Parse SEL data and stored in additionalDataMap
additionalDataMap parseAdditionalData(const ipmi::sel::AdditionalData& data)
{
    std::map<std::string, std::string> ret;

    for (const auto& d : data)
    {
        ret.insert(parseEntry(d));
    }
    return ret;
}
uint8_t convert(const std::string_view& str, int base = 10)
{
    int ret;
    std::from_chars(str.data(), str.data() + str.size(), ret, base);
    return static_cast<uint8_t>(ret);
}

// Convert the string to a vector of uint8_t, where the str is formatted as hex
std::vector<uint8_t> convertVec(const std::string_view& str)
{
    std::vector<uint8_t> ret;
    auto len = str.size() / 2;
    ret.reserve(len);
    for (size_t i = 0; i < len; ++i)
    {
        ret.emplace_back(convert(str.substr(i * 2, 2), 16));
    }
    return ret;
}

std::chrono::milliseconds getEntryData(const std::string& objPath,
                                       entryDataMap& entryData,
                                       uint16_t& recordId)
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    auto service = ipmi::getService(bus, ipmi::sel::logEntryIntf, objPath);

    // Read all the log entry properties.
    auto methodCall = bus.new_method_call(service.c_str(), objPath.c_str(),
                                          ipmi::sel::propIntf, "GetAll");
    methodCall.append(ipmi::sel::logEntryIntf);

    auto reply = bus.call(methodCall);
    if (reply.is_method_error())
    {
        log<level::ERR>("Error in reading logging property entries");
        elog<InternalFailure>();
    }

    reply.read(entryData);
    // Read Id from the log entry.
    static constexpr auto propId = "Id";
    auto iterId = entryData.find(propId);
    if (iterId == entryData.end())
    {
        log<level::ERR>("Error in reading Id of logging entry");
        elog<InternalFailure>();
    }
    recordId = static_cast<uint16_t>(std::get<uint32_t>(iterId->second));

    // Read Timestamp from the log entry.
    static constexpr auto propTimeStamp = "Timestamp";
    auto iterTimeStamp = entryData.find(propTimeStamp);
    if (iterTimeStamp == entryData.end())
    {
        log<level::ERR>("Error in reading Timestamp of logging entry");
        elog<InternalFailure>();
    }
    std::chrono::milliseconds chronoTimeStamp(
        std::get<uint64_t>(iterTimeStamp->second));
    return chronoTimeStamp;
}

ipmi::sel::GetSELEntryResponse createSELEntry(const std::string& objPath)
{
    ipmi::sel::GetSELEntryResponse record{};

    uint16_t recordId;
    entryDataMap entryData;
    std::chrono::milliseconds chronoTimeStamp =
        getEntryData(objPath, entryData, recordId);

    record.event.eventRecord.recordID = recordId;
    additionalDataMap m;
    auto iterData = entryData.find(propAdditionalData);
    if (iterData == entryData.end())
    {
        log<level::ERR>("SEL AdditionalData  Not available");
        return record;
    }

    const auto& addData = std::get<ipmi::sel::AdditionalData>(iterData->second);
    m = parseAdditionalData(addData);
    auto recordType = static_cast<uint8_t>(convert(m[strRecordType]));
    if (recordType != systemEventRecord)
    {
        log<level::ERR>("Invalid recordType");
        return record;
    }
    // Default values when there is no matched sensor
    record.event.eventRecord.sensorType = 0;
    record.event.eventRecord.sensorNum = 0xFF;
    record.event.eventRecord.eventType = 0;
    std::string sensorPath("");
    auto iter = m.find(strSensorPath);
    if (iter != m.end())
    {
        sensorPath = iter->second;
    }
    else
    {
        log<level::ERR>("Event not from matched sensor, Hence logging it with "
                        "default values");
    }

    if (!sensorPath.empty())
    {
        try
        {
            record.event.eventRecord.sensorNum =
                getSensorNumberFromPath(sensorPath);
            record.event.eventRecord.eventType =
                getSensorEventTypeFromPath(sensorPath);
            record.event.eventRecord.sensorType =
                getSensorTypeFromPath(sensorPath);
        }
        catch (...)
        {
            log<level::ERR>("Failed to get dynamic sensor properties");
            elog<InternalFailure>();
        }
    }
    record.event.eventRecord.eventMsgRevision = eventMsgRevision;
    record.event.eventRecord.generatorID = 0;

    iter = m.find(ami::ipmi::sel::strGenerateId);
    if (iter != m.end())
    {
        record.event.eventRecord.generatorID =
            static_cast<uint16_t>(convert(iter->second));
    }

    iter = m.find(ami::ipmi::sel::strEventDir);
    if (iter != m.end())
    {
        auto eventDir = static_cast<uint8_t>(convert(iter->second));
        uint8_t assert = eventDir ? assertEvent : deassertEvent;
        record.event.eventRecord.eventType |= assert;
    }

    record.event.eventRecord.recordType = recordType;
    record.event.eventRecord.timeStamp = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(chronoTimeStamp)
            .count());

    auto sensorData = std::vector<unsigned char>(0);
    iter = m.find(ami::ipmi::sel::strSensorData);
    if (iter != m.end())
        sensorData = convertVec(iter->second);

    iter = m.find("SENSOR_TYPE");
    if (iter != m.end())
    {
        record.event.eventRecord.sensorType =
            static_cast<uint8_t>(std::stoi(iter->second));
        record.event.eventRecord.eventType =
            getEventType(record.event.eventRecord.sensorType);
    }
    iter = m.find(strSensorData);
    if (iter != m.end())
        sensorData = convertVec(iter->second);
    record.event.eventRecord.eventData1 = static_cast<uint8_t>(0x50);

    // The remaining 3 bytes are the sensor data
    memcpy(&record.event.eventRecord.eventData1, sensorData.data(),
           std::min(sensorData.size(),
                    static_cast<size_t>(ami::ipmi::sel::selDataSize)));

    return record;
}

std::optional<std::pair<uint16_t, SELEntry>>
    parseLoggingEntry(const std::string& p)
{
    try
    {
        auto id = getLoggingId(p);
        ipmi::sel::GetSELEntryResponse record{};
        record = createSELEntry(p);
        return std::pair<uint16_t, SELEntry>({id, std::move(record.event)});
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "Failed to convert %s to SEL: %s\n", p.c_str(),
                e.what());
    }
    return std::nullopt;
}

void saveEraseTimeStamp()
{
    std::filesystem::path path(ami::ipmi::sel::selEraseTimestamp);
    std::ofstream eraseTimeFile(path);
    if (!eraseTimeFile.good())
    {
        std::cerr << "Failed to open sel_erase_time file";
    }

    eraseTimeFile.close();
}

void selAddedCallback(sdbusplus::message::message& m)
{
    sdbusplus::message::object_path objPath;
    try
    {
        m.read(objPath);
    }
    catch (const sdbusplus::exception::exception& e)
    {
        log<level::ERR>("Failed to read object path");
        return;
    }
    std::string p = objPath;
    auto entry = parseLoggingEntry(p);
    if (entry)
    {
        selCacheMap.insert(std::move(*entry));
    }
}

void selRemovedCallback(sdbusplus::message::message& m)
{
    sdbusplus::message::object_path objPath;
    try
    {
        m.read(objPath);
    }
    catch (const sdbusplus::exception::exception& e)
    {
        log<level::ERR>("Failed to read object path");
    }
    try
    {
        std::string p = objPath;
        selCacheMap.erase(getLoggingId(p));
        saveEraseTimeStamp();
    }
    catch (const std::invalid_argument& e)
    {
        log<level::ERR>("Invalid logging entry ID");
    }
}

void selUpdatedCallback(sdbusplus::message::message& m)
{
    std::string p = m.get_path();
    auto entry = parseLoggingEntry(p);
    if (entry)
    {
        selCacheMap.insert_or_assign(entry->first, std::move(entry->second));
    }
}

void registerSelCallbackHandler()
{
    using namespace sdbusplus::bus::match::rules;
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    if (!selAddedMatch)
    {
        selAddedMatch = std::make_unique<sdbusplus::bus::match::match>(
            bus, interfacesAdded("/xyz/openbmc_project/logging"),
            std::bind(selAddedCallback, std::placeholders::_1));
    }
    if (!selRemovedMatch)
    {
        selRemovedMatch = std::make_unique<sdbusplus::bus::match::match>(
            bus, interfacesRemoved("/xyz/openbmc_project/logging"),
            std::bind(selRemovedCallback, std::placeholders::_1));
    }
    if (!selUpdatedMatch)
    {
        selUpdatedMatch = std::make_unique<sdbusplus::bus::match::match>(
            bus,
            type::signal() + member("PropertiesChanged"s) +
                interface("org.freedesktop.DBus.Properties"s) +
                argN(0, "xyz.openbmc_project.Logging.Entry"),
            std::bind(selUpdatedCallback, std::placeholders::_1));
    }
}

void initSELCache()
{
    registerSelCallbackHandler();
    ipmi::sel::ObjectPaths paths;
    try
    {
        readLoggingObjectPathst(paths);
    }
    catch (const sdbusplus::exception::exception& e)
    {
        log<level::ERR>("Failed to get logging object paths");
        return;
    }
    for (const auto& p : paths)
    {
        auto entry = parseLoggingEntry(p);
        if (entry)
        {
            selCacheMap.insert(std::move(*entry));
        }
    }
    selCacheMapInitialized = true;
}


namespace intel_oem::ipmi::sel
{
static const std::filesystem::path selLogDir = "/var/log";
static const std::string selLogFilename = "ipmi_sel";

static int getFileTimestamp(const std::filesystem::path& file)
{
    struct stat st;

    if (stat(file.c_str(), &st) >= 0)
    {
        return st.st_mtime;
    }
    return ::ipmi::sel::invalidTimeStamp;
}

namespace erase_time
{
static constexpr const char* selEraseTimestamp = "/var/lib/ipmi/sel_erase_time";

void save()
{
    // open the file, creating it if necessary
    int fd = open(selEraseTimestamp, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        std::cerr << "Failed to open file\n";
        return;
    }

    // update the file timestamp to the current time
    if (futimens(fd, NULL) < 0)
    {
        std::cerr << "Failed to update timestamp: "
                  << std::string(strerror(errno));
    }
    close(fd);
}

int get()
{
    return getFileTimestamp(selEraseTimestamp);
}
} // namespace erase_time
} // namespace intel_oem::ipmi::sel

namespace ipmi
{

namespace storage
{

constexpr static const size_t maxMessageSize = 64;
constexpr static const size_t maxFruSdrNameSize = 16;
using ObjectType = boost::container::flat_map<
    std::string, boost::container::flat_map<std::string, DbusVariant>>;
using ManagedObjectType =
    boost::container::flat_map<sdbusplus::message::object_path, ObjectType>;
using ManagedEntry = std::pair<sdbusplus::message::object_path, ObjectType>;
using GetObjectType =
    std::vector<std::pair<std::string, std::vector<std::string>>>;

constexpr static const char* fruDeviceServiceName =
    "xyz.openbmc_project.FruDevice";
constexpr static const size_t writeTimeoutSeconds = 10;
constexpr static const char* chassisTypeRackMount = "23";

// event direction is bit[7] of eventType where 1b = Deassertion event
constexpr static const uint8_t deassertionEvent = 0x80;

static std::vector<uint8_t> fruCache;
static uint16_t cacheBus = 0xFFFF;
static uint8_t cacheAddr = 0XFF;
static uint8_t lastDevId = 0xFF;

static uint16_t writeBus = 0xFFFF;
static uint8_t writeAddr = 0XFF;

std::unique_ptr<sdbusplus::Timer> writeTimer = nullptr;
static std::vector<sdbusplus::bus::match_t> fruMatches;

ManagedObjectType frus;

// we unfortunately have to build a map of hashes in case there is a
// collision to verify our dev-id
boost::container::flat_map<uint8_t, std::pair<uint16_t, uint8_t>> deviceHashes;
// Map devId to Object Path
boost::container::flat_map<uint8_t, std::string> devicePath;

void registerStorageFunctions() __attribute__((constructor));

bool writeFru()
{
    if (writeBus == 0xFFFF && writeAddr == 0xFF)
    {
        return true;
    }
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    sdbusplus::message_t writeFru = dbus->new_method_call(
        fruDeviceServiceName, "/xyz/openbmc_project/FruDevice",
        "xyz.openbmc_project.FruDeviceManager", "WriteFru");
    writeFru.append(writeBus, writeAddr, fruCache);
    try
    {
        sdbusplus::message_t writeFruResp = dbus->call(writeFru);
    }
    catch (const sdbusplus::exception_t&)
    {
        // todo: log sel?
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "error writing fru");
        return false;
    }
    writeBus = 0xFFFF;
    writeAddr = 0xFF;
    return true;
}

void createTimers()
{
    writeTimer = std::make_unique<sdbusplus::Timer>(writeFru);
}

void recalculateHashes()
{
    deviceHashes.clear();
    devicePath.clear();
    // hash the object paths to create unique device id's. increment on
    // collision
    std::hash<std::string> hasher;
    for (const auto& fru : frus)
    {
        auto fruIface = fru.second.find("xyz.openbmc_project.FruDevice");
        if (fruIface == fru.second.end())
        {
            continue;
        }

        auto busFind = fruIface->second.find("BUS");
        auto addrFind = fruIface->second.find("ADDRESS");
        if (busFind == fruIface->second.end() ||
            addrFind == fruIface->second.end())
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "fru device missing Bus or Address",
                phosphor::logging::entry("FRU=%s", fru.first.str.c_str()));
            continue;
        }

        uint16_t fruBus = std::get<uint32_t>(busFind->second);
        uint8_t fruAddr = std::get<uint32_t>(addrFind->second);
        auto chassisFind = fruIface->second.find("CHASSIS_TYPE");
        std::string chassisType;
        if (chassisFind != fruIface->second.end())
        {
            chassisType = std::get<std::string>(chassisFind->second);
        }

        uint8_t fruHash = 0;
        if (chassisType.compare(chassisTypeRackMount) != 0)
        {
            fruHash = hasher(fru.first.str);
            // can't be 0xFF based on spec, and 0 is reserved for baseboard
            if (fruHash == 0 || fruHash == 0xFF)
            {
                fruHash = 1;
            }
        }
        std::pair<uint16_t, uint8_t> newDev(fruBus, fruAddr);

        bool emplacePassed = false;
        while (!emplacePassed)
        {
            auto resp = deviceHashes.emplace(fruHash, newDev);

            devicePath.emplace(fruHash, fru.first);

            emplacePassed = resp.second;
            if (!emplacePassed)
            {
                fruHash++;
                // can't be 0xFF based on spec, and 0 is reserved for
                // baseboard
                if (fruHash == 0XFF)
                {
                    fruHash = 0x1;
                }
            }
        }
    }
}

void replaceCacheFru(const std::shared_ptr<sdbusplus::asio::connection>& bus,
                     boost::asio::yield_context& yield)
{
    boost::system::error_code ec;
    // ObjectPaths and Services which implements "xyz.openbmc_project.FruDevice"
    // interface
    GetSubTreeType fruServices = bus->yield_method_call<GetSubTreeType>(
        yield, ec, "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree", "/", 0,
        std::array<const char*, 1>{"xyz.openbmc_project.FruDevice"});

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetSubTree failed for FruDevice Interface ",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));

        return;
    }
    // Get List of services which have implemented FruDevice interface
    std::unordered_set<std::string> services;
    for (const auto& [path, serviceMap] : fruServices)
    {
        for (const auto& [service, interfaces] : serviceMap)
        {
            services.insert(service);
        }
    }

    // GetAll the objects under services which implement FruDevice interface
    for (const std::string& service : services)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::success);
        ManagedObjectType obj = bus->yield_method_call<ManagedObjectType>(
            yield, ec, service, "/", "org.freedesktop.DBus.ObjectManager",
            "GetManagedObjects");
        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "GetMangagedObjects failed",
                phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
            continue;
        }
        // Save the object path which has FruDevice interface
        for (const auto& [path, serviceMap] : fruServices)
        {
            for (const auto& serv : serviceMap)
            {
                if (serv.first == service)
                {
                    auto fru = obj.find(path);
                    if (fru == obj.end())
                    {
                        continue;
                    }
                    frus.emplace(fru->first, fru->second);
                }
            }
        }
    }

    recalculateHashes();
}

ipmi::Cc getFru(ipmi::Context::ptr& ctx, uint8_t devId)
{
    if (lastDevId == devId && devId != 0xFF)
    {
        return ipmi::ccSuccess;
    }

    auto deviceFind = deviceHashes.find(devId);
    auto devPath = devicePath.find(devId);
    if (deviceFind == deviceHashes.end() || devPath == devicePath.end())
    {
        return IPMI_CC_SENSOR_INVALID;
    }

    if (writeTimer->isRunning())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Couldn't get raw fru as fru is updating");
        return ipmi::ccBusy;
    }
    fruCache.clear();

    cacheBus = deviceFind->second.first;
    cacheAddr = deviceFind->second.second;

    boost::system::error_code ec;
    GetObjectType fruService = ctx->bus->yield_method_call<GetObjectType>(
        ctx->yield, ec, "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetObject", devPath->second,
        std::array<const char*, 1>{"xyz.openbmc_project.FruDevice"});

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Couldn't get raw fru because of service",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        return ipmi::ccResponseError;
    }

    bool foundFru = false;
    for (auto& service : fruService)
    {
        fruCache = ctx->bus->yield_method_call<std::vector<uint8_t>>(
            ctx->yield, ec, service.first, "/xyz/openbmc_project/FruDevice",
            "xyz.openbmc_project.FruDeviceManager", "GetRawFru", cacheBus,
            cacheAddr);

        if (!ec)
        {
            foundFru = true;
            break;
        }
    }

    if (!foundFru)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Couldn't get raw fru",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        cacheBus = 0xFFFF;
        cacheAddr = 0xFF;
        return ipmi::ccResponseError;
    }

    lastDevId = devId;
    return ipmi::ccSuccess;
}

void writeFruIfRunning()
{
    if (!writeTimer->isRunning())
    {
        return;
    }
    writeTimer->stop();
    writeFru();
}

void startMatch(void)
{
    if (fruMatches.size())
    {
        return;
    }

    fruMatches.reserve(2);

    auto bus = getSdBus();
    fruMatches.emplace_back(*bus,
                            "type='signal',arg0path='/xyz/openbmc_project/"
                            "FruDevice/',member='InterfacesAdded'",
                            [](sdbusplus::message_t& message) {
        sdbusplus::message::object_path path;
        ObjectType object;
        try
        {
            message.read(path, object);
        }
        catch (const sdbusplus::exception_t&)
        {
            return;
        }
        auto findType = object.find("xyz.openbmc_project.FruDevice");
        if (findType == object.end())
        {
            return;
        }
        writeFruIfRunning();
        frus[path] = object;
        recalculateHashes();
        lastDevId = 0xFF;
    });

    fruMatches.emplace_back(*bus,
                            "type='signal',arg0path='/xyz/openbmc_project/"
                            "FruDevice/',member='InterfacesRemoved'",
                            [](sdbusplus::message_t& message) {
        sdbusplus::message::object_path path;
        std::set<std::string> interfaces;
        try
        {
            message.read(path, interfaces);
        }
        catch (const sdbusplus::exception_t&)
        {
            return;
        }
        auto findType = interfaces.find("xyz.openbmc_project.FruDevice");
        if (findType == interfaces.end())
        {
            return;
        }
        writeFruIfRunning();
        frus.erase(path);
        recalculateHashes();
        lastDevId = 0xFF;
    });

    // call once to populate
    boost::asio::spawn(*getIoContext(), [](boost::asio::yield_context yield) {
        replaceCacheFru(getSdBus(), yield);
    });
}

/** @brief implements the read FRU data command
 *  @param fruDeviceId        - FRU Device ID
 *  @param fruInventoryOffset - FRU Inventory Offset to write
 *  @param countToRead        - Count to read
 *
 *  @returns ipmi completion code plus response data
 *   - countWritten  - Count written
 */
ipmi::RspType<uint8_t,             // Count
              std::vector<uint8_t> // Requested data
              >
    ipmiStorageReadFruData(ipmi::Context::ptr& ctx, uint8_t fruDeviceId,
                           uint16_t fruInventoryOffset, uint8_t countToRead)
{
    if (fruDeviceId == 0xFF)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    ipmi::Cc status = getFru(ctx, fruDeviceId);

    if (status != ipmi::ccSuccess)
    {
        return ipmi::response(status);
    }

    size_t fromFruByteLen = 0;
    if (countToRead + fruInventoryOffset < fruCache.size())
    {
        fromFruByteLen = countToRead;
    }
    else if (fruCache.size() > fruInventoryOffset)
    {
        fromFruByteLen = fruCache.size() - fruInventoryOffset;
    }
    else
    {
        return ipmi::responseReqDataLenExceeded();
    }

    std::vector<uint8_t> requestedData;

    requestedData.insert(
        requestedData.begin(), fruCache.begin() + fruInventoryOffset,
        fruCache.begin() + fruInventoryOffset + fromFruByteLen);

    return ipmi::responseSuccess(static_cast<uint8_t>(requestedData.size()),
                                 requestedData);
}

/** @brief implements the write FRU data command
 *  @param fruDeviceId        - FRU Device ID
 *  @param fruInventoryOffset - FRU Inventory Offset to write
 *  @param dataToWrite        - Data to write
 *
 *  @returns ipmi completion code plus response data
 *   - countWritten  - Count written
 */
ipmi::RspType<uint8_t>
    ipmiStorageWriteFruData(ipmi::Context::ptr& ctx, uint8_t fruDeviceId,
                            uint16_t fruInventoryOffset,
                            std::vector<uint8_t>& dataToWrite)
{
    if (fruDeviceId == 0xFF)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    size_t writeLen = dataToWrite.size();

    ipmi::Cc status = getFru(ctx, fruDeviceId);
    if (status != ipmi::ccSuccess)
    {
        return ipmi::response(status);
    }
    size_t lastWriteAddr = fruInventoryOffset + writeLen;
    if (fruCache.size() < lastWriteAddr)
    {
        fruCache.resize(fruInventoryOffset + writeLen);
    }

    std::copy(dataToWrite.begin(), dataToWrite.begin() + writeLen,
              fruCache.begin() + fruInventoryOffset);

    bool atEnd = validateBasicFruContent(fruCache, lastWriteAddr);
    uint8_t countWritten = 0;

    writeBus = cacheBus;
    writeAddr = cacheAddr;
    if (atEnd)
    {
        // cancel timer, we're at the end so might as well send it
        writeTimer->stop();
        if (!writeFru())
        {
            return ipmi::responseInvalidFieldRequest();
        }
        countWritten = std::min(dataToWrite.size(), static_cast<size_t>(0xFF));
    }
    else
    {
        // start a timer, if no further data is sent  to check to see if it is
        // valid
        writeTimer->start(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::seconds(writeTimeoutSeconds)));
        countWritten = 0;
    }

    return ipmi::responseSuccess(countWritten);
}

/** @brief implements the get FRU inventory area info command
 *  @param fruDeviceId  - FRU Device ID
 *
 *  @returns IPMI completion code plus response data
 *   - inventorySize - Number of possible allocation units
 *   - accessType    - Allocation unit size in bytes.
 */
ipmi::RspType<uint16_t, // inventorySize
              uint8_t>  // accessType
    ipmiStorageGetFruInvAreaInfo(ipmi::Context::ptr& ctx, uint8_t fruDeviceId)
{
    if (fruDeviceId == 0xFF)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    ipmi::Cc ret = getFru(ctx, fruDeviceId);
    if (ret != ipmi::ccSuccess)
    {
        return ipmi::response(ret);
    }

    constexpr uint8_t accessType =
        static_cast<uint8_t>(GetFRUAreaAccessType::byte);

    return ipmi::responseSuccess(fruCache.size(), accessType);
}

ipmi::Cc getFruSdrCount(ipmi::Context::ptr&, size_t& count)
{
    count = deviceHashes.size();
    return ipmi::ccSuccess;
}

ipmi::Cc getFruSdrs(ipmi::Context::ptr& ctx, size_t index,
                    get_sdr::SensorDataFruRecord& resp)
{
    if (deviceHashes.size() < index)
    {
        return ipmi::ccInvalidFieldRequest;
    }
    auto device = deviceHashes.begin() + index;
    uint16_t& bus = device->second.first;
    uint8_t& address = device->second.second;

    boost::container::flat_map<std::string, DbusVariant>* fruData = nullptr;
    auto fru = std::find_if(frus.begin(), frus.end(),
                            [bus, address, &fruData](ManagedEntry& entry) {
        auto findFruDevice = entry.second.find("xyz.openbmc_project.FruDevice");
        if (findFruDevice == entry.second.end())
        {
            return false;
        }
        fruData = &(findFruDevice->second);
        auto findBus = findFruDevice->second.find("BUS");
        auto findAddress = findFruDevice->second.find("ADDRESS");
        if (findBus == findFruDevice->second.end() ||
            findAddress == findFruDevice->second.end())
        {
            return false;
        }
        if (std::get<uint32_t>(findBus->second) != bus)
        {
            return false;
        }
        if (std::get<uint32_t>(findAddress->second) != address)
        {
            return false;
        }
        return true;
    });
    if (fru == frus.end())
    {
        return ipmi::ccResponseError;
    }

#ifdef USING_ENTITY_MANAGER_DECORATORS

    boost::container::flat_map<std::string, DbusVariant>* entityData = nullptr;

    // todo: this should really use caching, this is a very inefficient lookup
    boost::system::error_code ec;
    ManagedObjectType entities = ctx->bus->yield_method_call<ManagedObjectType>(
        ctx->yield, ec, "xyz.openbmc_project.EntityManager",
        "/xyz/openbmc_project/inventory", "org.freedesktop.DBus.ObjectManager",
        "GetManagedObjects");

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetMangagedObjects for getSensorMap failed",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));

        return ipmi::ccResponseError;
    }

    auto entity =
        std::find_if(entities.begin(), entities.end(),
                     [bus, address, &entityData](ManagedEntry& entry) {
        auto findFruDevice = entry.second.find(
            "xyz.openbmc_project.Inventory.Decorator.FruDevice");
        if (findFruDevice == entry.second.end())
        {
            return false;
        }

        // Integer fields added via Entity-Manager json are uint64_ts by
        // default.
        auto findBus = findFruDevice->second.find("Bus");
        auto findAddress = findFruDevice->second.find("Address");

        if (findBus == findFruDevice->second.end() ||
            findAddress == findFruDevice->second.end())
        {
            return false;
        }
        if ((std::get<uint64_t>(findBus->second) != bus) ||
            (std::get<uint64_t>(findAddress->second) != address))
        {
            return false;
        }

        // At this point we found the device entry and should return
        // true.
        auto findIpmiDevice =
            entry.second.find("xyz.openbmc_project.Inventory.Decorator.Ipmi");
        if (findIpmiDevice != entry.second.end())
        {
            entityData = &(findIpmiDevice->second);
        }

        return true;
    });

    if (entity == entities.end())
    {
        if constexpr (DEBUG)
        {
            std::fprintf(stderr, "Ipmi or FruDevice Decorator interface "
                                 "not found for Fru\n");
        }
    }

#endif

    std::string name;
    auto findProductName = fruData->find("BOARD_PRODUCT_NAME");
    auto findBoardName = fruData->find("PRODUCT_PRODUCT_NAME");
    if (findProductName != fruData->end())
    {
        name = std::get<std::string>(findProductName->second);
    }
    else if (findBoardName != fruData->end())
    {
        name = std::get<std::string>(findBoardName->second);
    }
    else
    {
        name = "UNKNOWN";
    }
    if (name.size() > maxFruSdrNameSize)
    {
        name = name.substr(0, maxFruSdrNameSize);
    }
    size_t sizeDiff = maxFruSdrNameSize - name.size();

    resp.header.record_id_lsb = 0x0; // calling code is to implement these
    resp.header.record_id_msb = 0x0;
    resp.header.sdr_version = ipmiSdrVersion;
    resp.header.record_type = get_sdr::SENSOR_DATA_FRU_RECORD;
    resp.header.record_length = sizeof(resp.body) + sizeof(resp.key) - sizeDiff;
    resp.key.deviceAddress = 0x20;
    resp.key.fruID = device->first;
    resp.key.accessLun = 0x80; // logical / physical fru device
    resp.key.channelNumber = 0x0;
    resp.body.reserved = 0x0;
    resp.body.deviceType = 0x10;
    resp.body.deviceTypeModifier = 0x0;

    uint8_t entityID = 0;
    uint8_t entityInstance = 0x1;

#ifdef USING_ENTITY_MANAGER_DECORATORS
    if (entityData)
    {
        auto entityIdProperty = entityData->find("EntityId");
        auto entityInstanceProperty = entityData->find("EntityInstance");

        if (entityIdProperty != entityData->end())
        {
            entityID = static_cast<uint8_t>(
                std::get<uint64_t>(entityIdProperty->second));
        }
        if (entityInstanceProperty != entityData->end())
        {
            entityInstance = static_cast<uint8_t>(
                std::get<uint64_t>(entityInstanceProperty->second));
        }
    }
#endif

    resp.body.entityID = entityID;
    resp.body.entityInstance = entityInstance;

    resp.body.oem = 0x0;
    resp.body.deviceIDLen = name.size();
    name.copy(resp.body.deviceID, name.size());

    return ipmi::ccSuccess;
}

static bool getSELLogFiles(std::vector<std::filesystem::path>& selLogFiles)
{
    // Loop through the directory looking for ipmi_sel log files
    for (const std::filesystem::directory_entry& dirEnt :
         std::filesystem::directory_iterator(intel_oem::ipmi::sel::selLogDir))
    {
        std::string filename = dirEnt.path().filename();
        if (boost::starts_with(filename, intel_oem::ipmi::sel::selLogFilename))
        {
            // If we find an ipmi_sel log file, save the path
            selLogFiles.emplace_back(intel_oem::ipmi::sel::selLogDir /
                                     filename);
        }
    }
    // As the log files rotate, they are appended with a ".#" that is higher for
    // the older logs. Since we don't expect more than 10 log files, we
    // can just sort the list to get them in order from newest to oldest
    std::sort(selLogFiles.begin(), selLogFiles.end());

    return !selLogFiles.empty();
}

[[maybe_unused]] static int countSELEntries()
{
    // Get the list of ipmi_sel log files
    std::vector<std::filesystem::path> selLogFiles;
    if (!getSELLogFiles(selLogFiles))
    {
        return 0;
    }
    int numSELEntries = 0;
    // Loop through each log file and count the number of logs
    for (const std::filesystem::path& file : selLogFiles)
    {
        std::ifstream logStream(file);
        if (!logStream.is_open())
        {
            continue;
        }

        std::string line;
        while (std::getline(logStream, line))
        {
            numSELEntries++;
        }
    }
    return numSELEntries;
}

static bool findSELEntry(const int recordID,
                         const std::vector<std::filesystem::path>& selLogFiles,
                         std::string& entry)
{
    // Record ID is the first entry field following the timestamp. It is
    // preceded by a space and followed by a comma
    std::string search = " " + std::to_string(recordID) + ",";

    // Loop through the ipmi_sel log entries
    for (const std::filesystem::path& file : selLogFiles)
    {
        std::ifstream logStream(file);
        if (!logStream.is_open())
        {
            continue;
        }

        while (std::getline(logStream, entry))
        {
            // Check if the record ID matches
            if (entry.find(search) != std::string::npos)
            {
                return true;
            }
        }
    }
    return false;
}

[[maybe_unused]] static uint16_t
    getNextRecordID(const uint16_t recordID,
                    const std::vector<std::filesystem::path>& selLogFiles)
{
    uint16_t nextRecordID = recordID + 1;
    std::string entry;
    if (findSELEntry(nextRecordID, selLogFiles, entry))
    {
        return nextRecordID;
    }
    else
    {
        return ipmi::sel::lastEntry;
    }
}

[[maybe_unused]] static int fromHexStr(const std::string& hexStr, std::vector<uint8_t>& data)
{
    for (unsigned int i = 0; i < hexStr.size(); i += 2)
    {
        try
        {
            data.push_back(static_cast<uint8_t>(
                std::stoul(hexStr.substr(i, 2), nullptr, 16)));
        }
        catch (const std::invalid_argument& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return -1;
        }
        catch (const std::out_of_range& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return -1;
        }
    }
    return 0;
}

ipmi::RspType<uint8_t,  // SEL revision.
              uint16_t, // number of log entries in SEL.
              uint16_t, // free Space in bytes.
              uint32_t, // most recent addition timestamp
              uint32_t, // most recent erase timestamp.
              bool,     // SEL allocation info supported
              bool,     // reserve SEL supported
              bool,     // partial Add SEL Entry supported
              bool,     // delete SEL supported
              uint3_t,  // reserved
              bool      // overflow flag
              >
    ipmiStorageGetSELInfo()
{
    uint16_t entries = 0;
    // Most recent addition timestamp.
    uint32_t addTimeStamp = ipmi::sel::invalidTimeStamp;

    // Most recent delete timestamp
    uint32_t eraseTimeStamp = getFileTimestamp(selEraseTimestamp);

    if (!selCacheMapInitialized)
    {
        // In case the initSELCache() fails, try it again
        initSELCache();
    }
    if (!selCacheMap.empty())
    {
        entries = static_cast<uint16_t>(selCacheMap.size());

        try
        {
            auto objPath = getLoggingObjPath(selCacheMap.rbegin()->first);
            addTimeStamp =
                static_cast<uint32_t>(getEntryTimeStamp(objPath).count());
        }
        catch (const std::runtime_error& e)
        {
            log<level::ERR>(e.what());
        }
    }
    constexpr uint8_t selVersion = ipmi::sel::selVersion;
    uint16_t freeSpace = ((InfoEventEntries + ErrorEventEntries) - entries) *
                         ipmi::sel::selRecordSize;
    constexpr uint3_t reserved{0};

    return ipmi::responseSuccess(
        selVersion, entries, freeSpace, addTimeStamp, eraseTimeStamp,
        ipmi::sel::operationSupport::getSelAllocationInfo,
        ipmi::sel::operationSupport::reserveSel,
        ipmi::sel::operationSupport::partialAddSelEntry,
        ipmi::sel::operationSupport::deleteSel, reserved,
        ipmi::sel::operationSupport::overflow);
}

using systemEventType = std::tuple<
    uint32_t, // Timestamp
    uint16_t, // Generator ID
    uint8_t,  // EvM Rev
    uint8_t,  // Sensor Type
    uint8_t,  // Sensor Number
    uint7_t,  // Event Type
    bool,     // Event Direction
    std::array<uint8_t, intel_oem::ipmi::sel::systemEventSize>>; // Event Data
using oemTsEventType = std::tuple<
    uint32_t,                                                    // Timestamp
    std::array<uint8_t, intel_oem::ipmi::sel::oemTsEventSize>>;  // Event Data
using oemEventType =
    std::array<uint8_t, intel_oem::ipmi::sel::oemEventSize>;     // Event Data

ipmi::RspType<uint16_t, // Next Record ID
              uint16_t, // Record ID
              uint8_t,  // Record Type
              std::variant<systemEventType, oemTsEventType,
                           oemEventType>> // Record Content
    ipmiStorageGetSELEntry(uint16_t reservationID, uint16_t selRecordID,
                          [[maybe_unused]] uint8_t offset,[[maybe_unused]] uint8_t readLength)
{
    if (reservationID != 0)
    {
        if (!checkSELReservation(reservationID))
        {
            return ipmi::responseInvalidReservationId();
        }
    }

    if (!selCacheMapInitialized)
    {
	    initSELCache();
	    selCacheMapInitialized = true;
    }

    if (selCacheMap.empty())
    {
        return ipmi::responseSensorInvalid();
    }

    SELCacheMap::const_iterator iter;
    if (selRecordID == ipmi::sel::firstEntry)
    {
        iter = selCacheMap.begin();
    }
    else if (selRecordID == ipmi::sel::lastEntry)
    {
        if (selCacheMap.size() > 1)
        {
            iter = selCacheMap.end();
            --iter;
        }
        else
        {
            // Only one entry exists, return the first
            iter = selCacheMap.begin();
        }
    }
    else
    {
        iter = selCacheMap.find(selRecordID);
        if (iter == selCacheMap.end())
        {
            return ipmi::responseSensorInvalid();
        }
    }
    ipmi::sel::GetSELEntryResponse record{0, iter->second};

    // Identify the next SEL record ID
    ++iter;

    if (iter == selCacheMap.end())
    {
        record.nextRecordID = ipmi::sel::lastEntry;
    }
    else
    {
        record.nextRecordID = iter->first;
    }

    bool eventDir = record.event.eventRecord.eventType >> 7;
    uint7_t eventType = record.event.eventRecord.eventType;
    std::array<uint8_t, 3> eventData{record.event.eventRecord.eventData1,
                                     record.event.eventRecord.eventData2,
                                     record.event.eventRecord.eventData3};
    return ipmi::responseSuccess(
        static_cast<uint16_t>(record.nextRecordID),
        static_cast<uint16_t>(record.event.eventRecord.recordID),
        static_cast<uint8_t>(record.event.eventRecord.recordType),
        systemEventType{
            static_cast<uint32_t>(record.event.eventRecord.timeStamp),
            static_cast<uint8_t>(record.event.eventRecord.generatorID),
            static_cast<uint8_t>(record.event.eventRecord.eventMsgRevision),
            static_cast<uint8_t>(record.event.eventRecord.sensorType),
            static_cast<uint8_t>(record.event.eventRecord.sensorNum), eventType,
            eventDir, eventData});
}

ipmi::RspType<uint16_t>
    ipmiStorageAddSELEntry(uint16_t recordID, uint8_t recordType,
                           [[maybe_unused]] uint32_t timeStamp, uint16_t generatorID,
                           [[maybe_unused]] uint8_t evmRev, uint8_t sensorType,
                           uint8_t sensorNumber, uint8_t eventDir,
                           std::array<uint8_t, eventDataSize> eventData)

{
    static constexpr auto systemRecordType = 0x02;
    cancelSELReservation();
    auto selDataStr = ipmi::sel::toHexStr(eventData);
    if (recordType == systemRecordType)
    {
        std::string objpath("");
        uint8_t typeFromPath;
        try
        {
            objpath = getPathFromSensorNumber(sensorNumber, sensorType);
            typeFromPath = getSensorTypeFromPath(objpath);
            if (typeFromPath !=
                sensorType) // if sensorType not matching, we assume sensor not
                            // available so prioprity is givien to IPMI Type
            {
                objpath.clear();
            }
        }
        catch (...)
        {
            log<level::ERR>("Failed to get sensor object path");
        }
        bool assert = (eventDir & 0x80) ? false : true;
        std::string redfishMessage = intel_oem::ipmi::sel::checkRedfishMessage(
            generatorID, sensorType, sensorNumber, eventDir, eventData[0]);

        sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());
        std::map<std::string, std::string> addData;
        addData["SENSOR_DATA"] = selDataStr.c_str();
        addData["SENSOR_PATH"] = objpath.c_str();
        addData["EVENT_DIR"] = std::to_string(assert);
        addData["GENERATOR_ID"] = std::to_string(generatorID);
        addData["RECORD_TYPE"] = std::to_string(recordType);
        addData["SENSOR_TYPE"] = std::to_string(sensorType);
        try
        {
            std::string service =
                ipmi::getService(bus, ipmiSELAddInterface, ipmiSELPath);
            auto addSEL =
                bus.new_method_call(service.c_str(), ipmiSELPath,
                                    ipmiSELAddInterface, "IpmiSelAdd");
            addSEL.append(redfishMessage, objpath.c_str(), eventData, assert,
                          generatorID, addData);
            bus.call_noreply(addSEL);
        }
        catch (const std::exception& e)
        {
            std::cerr << "Failed to create D-Bus log entry for SEL, ERROR="
                      << e.what() << "\n";
        }
    }
    else
        return ipmi::responseUnspecifiedError();

    if (selCacheMap.empty())
    {
        recordID = ami::ipmi::sel::firstEntryId;
        return ipmi::responseSuccess(recordID);
    }

    auto beginIter = selCacheMap.rbegin();
    recordID = beginIter->first;

    return ipmi::responseSuccess(++recordID);
}

ipmi::RspType<uint8_t> ipmiStorageClearSEL(uint16_t reservationID,
                                           const std::array<char, 3>& clr,
                                           uint8_t eraseOperation)

{
    static constexpr std::array<char, 3> clrOk = {'C', 'L', 'R'};
    if (clr != clrOk)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (!checkSELReservation(reservationID))
    {
        return ipmi::responseInvalidReservationId();
    }

    /*
     * Erasure status cannot be fetched from DBUS, so always return erasure
     * status as `erase completed`.
     */
    if (eraseOperation == ipmi::sel::getEraseStatus)
    {
        return ipmi::responseSuccess(
            static_cast<uint8_t>(ipmi::sel::eraseComplete));
    }
    // Per the IPMI spec, need to cancel any reservation when the SEL is cleared
    cancelSELReservation();

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    auto service = ipmi::getService(bus, ipmi::sel::logIntf, ipmi::sel::logObj);
    auto method =
        bus.new_method_call(service.c_str(), ipmi::sel::logObj,
                            ipmi::sel::logIntf, ipmi::sel::logDeleteAllMethod);
    try
    {
        bus.call_noreply(method);
    }
    catch (const sdbusplus::exception::exception& e)
    {
        log<level::ERR>("Error eraseAll ", entry("ERROR=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(
        static_cast<uint8_t>(ipmi::sel::eraseComplete));
}

/** @brief implements the delete SEL entry command
 * @request
 *   - reservationID; // reservation ID.
 *   - selRecordID;   // SEL record ID.
 *
 *  @returns ipmi completion code plus response data
 *   - Record ID of the deleted record
 */
ipmi::RspType<uint16_t // deleted record ID
              >
    deleteSELEntry(uint16_t reservationID, uint16_t selRecordID)
{
    namespace fs = std::filesystem;

    if (!checkSELReservation(reservationID))
    {
        return ipmi::responseInvalidReservationId();
    }

    // Per the IPMI spec, need to cancel the reservation when a SEL entry is
    // deleted
    cancelSELReservation();

    if (!selCacheMapInitialized)
    {
        // In case the initSELCache() fails, try it again
        initSELCache();
    }
    if (selCacheMap.empty())
    {
        return ipmi::responseSensorInvalid();
    }
    SELCacheMap::const_iterator iter;

    uint16_t delRecordID = 0;

    if (selRecordID == ipmi::sel::firstEntry)
    {
        delRecordID = selCacheMap.begin()->first;
    }
    else if (selRecordID == ipmi::sel::lastEntry)
    {
        delRecordID = selCacheMap.rbegin()->first;
    }
    else
    {
        delRecordID = selRecordID;
    }

    iter = selCacheMap.find(delRecordID);
    if (iter == selCacheMap.end())
    {
        return ipmi::responseSensorInvalid();
    }

    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    std::string service;

    auto objPath = getLoggingObjPath(iter->first);
    try
    {
        service = ipmi::getService(bus, ipmi::sel::logDeleteIntf, objPath);
    }
    catch (const std::runtime_error& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseUnspecifiedError();
    }

    auto methodCall = bus.new_method_call(service.c_str(), objPath.c_str(),
                                          ipmi::sel::logDeleteIntf, "Delete");
    try
    {
        auto reply = bus.call(methodCall);
    }	
    catch (const std::exception& e)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(delRecordID);
}

ipmi::RspType<uint32_t> ipmiStorageGetSELTime()
{
    struct timespec selTime = {};

    if (clock_gettime(CLOCK_REALTIME, &selTime) < 0)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(selTime.tv_sec);
}

std::vector<uint8_t> getType12SDRs(uint16_t index, uint16_t recordId)
{
    std::vector<uint8_t> resp;
    if (index == 0)
    {
        std::string bmcName = "Basbrd Mgmt Ctlr";
        Type12Record bmc(recordId, 0x20, 0, 0, 0xbf, 0x2e, 1, 0, bmcName);
        uint8_t* bmcPtr = reinterpret_cast<uint8_t*>(&bmc);
        resp.insert(resp.end(), bmcPtr, bmcPtr + sizeof(Type12Record));
    }
    else if (index == 1)
    {
        std::string meName = "Mgmt Engine";
        Type12Record me(recordId, 0x2c, 6, 0x24, 0x21, 0x2e, 2, 0, meName);
        uint8_t* mePtr = reinterpret_cast<uint8_t*>(&me);
        resp.insert(resp.end(), mePtr, mePtr + sizeof(Type12Record));
    }
    else
    {
        throw std::runtime_error("getType12SDRs:: Illegal index " +
                                 std::to_string(index));
    }

    return resp;
}

std::vector<uint8_t> getNMDiscoverySDR(uint16_t index, uint16_t recordId)
{
    std::vector<uint8_t> resp;
    if (index == 0)
    {
        NMDiscoveryRecord nm = {};
        nm.header.record_id_lsb = recordId;
        nm.header.record_id_msb = recordId >> 8;
        nm.header.sdr_version = ipmiSdrVersion;
        nm.header.record_type = 0xC0;
        nm.header.record_length = 0xB;
        nm.oemID0 = 0x57;
        nm.oemID1 = 0x1;
        nm.oemID2 = 0x0;
        nm.subType = 0x0D;
        nm.version = 0x1;
        nm.targetAddress = 0x2C;
        nm.channelNumber = 0x60;
        nm.healthEventSensor = 0x19;
        nm.exceptionEventSensor = 0x18;
        nm.operationalCapSensor = 0x1A;
        nm.thresholdExceededSensor = 0x1B;

        uint8_t* nmPtr = reinterpret_cast<uint8_t*>(&nm);
        resp.insert(resp.end(), nmPtr, nmPtr + sizeof(NMDiscoveryRecord));
    }
    else
    {
        throw std::runtime_error("getNMDiscoverySDR:: Illegal index " +
                                 std::to_string(index));
    }

    return resp;
}

void registerStorageFunctions()
{
    createTimers();
    startMatch();

    // <Get FRU Inventory Area Info>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetFruInventoryAreaInfo,
                          ipmi::Privilege::User, ipmiStorageGetFruInvAreaInfo);
    // <READ FRU Data>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdReadFruData, ipmi::Privilege::User,
                          ipmiStorageReadFruData);

    // <WRITE FRU Data>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdWriteFruData,
                          ipmi::Privilege::Operator, ipmiStorageWriteFruData);

    // <Get SEL Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelInfo, ipmi::Privilege::User,
                          ipmiStorageGetSELInfo);

    // <Get SEL Entry>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelEntry, ipmi::Privilege::User,
                          ipmiStorageGetSELEntry);

    // <Add SEL Entry>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdAddSelEntry,
                          ipmi::Privilege::Operator, ipmiStorageAddSELEntry);

    // <Clear SEL>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdClearSel, ipmi::Privilege::Operator,
                          ipmiStorageClearSEL);

    // <Delete SEL Entry>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdDeleteSelEntry,
                          ipmi::Privilege::Operator, deleteSELEntry);

    // <Get SEL Time>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelTime, ipmi::Privilege::User,
                          ipmiStorageGetSELTime);

}
} // namespace storage
} // namespace ipmi

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

#pragma once
#include <phosphor-ipmi-host/sensorhandler.hpp>

#include <cstdint>

static constexpr uint8_t ipmiSdrVersion = 0x51;
static constexpr uint8_t eventDataSize = 3;

namespace intel_oem::ipmi::sel
{
static constexpr uint8_t selOperationSupport = 0x02;
static constexpr uint8_t systemEvent = 0x02;
static constexpr size_t systemEventSize = 3;
static constexpr uint8_t oemTsEventFirst = 0xC0;
static constexpr uint8_t oemTsEventLast = 0xDF;
static constexpr size_t oemTsEventSize = 9;
static constexpr uint8_t oemEventFirst = 0xE0;
static constexpr uint8_t oemEventLast = 0xFF;
static constexpr size_t oemEventSize = 13;
static constexpr uint8_t eventMsgRev = 0x04;
} // namespace intel_oem::ipmi::sel

namespace ami::ipmi::sel
{
constexpr auto systemEventRecord = 0x02;
constexpr auto generatorID = 0x2000;
constexpr auto eventMsgRevision = 0x04;
constexpr auto assertEvent = 0x00;
constexpr auto deassertEvent = 0x80;
constexpr auto selDataSize = 3;
constexpr auto oemCDDataSize = 9;
constexpr auto oemEFDataSize = 13;

constexpr auto propAdditionalData = "AdditionalData";
constexpr auto propResolved = "Resolved";
constexpr auto propSeverity = "Severity";

constexpr auto strEventType = "EVENT_TYPE";
constexpr auto strEventDir = "EVENT_DIR";
constexpr auto strGenerateId = "GENERATOR_ID";
constexpr auto strRecordType = "RECORD_TYPE";
constexpr auto strSensorData = "SENSOR_DATA";
constexpr auto strSensorPath = "SENSOR_PATH";
constexpr auto strSensorType = "SENSOR_TYPE";

constexpr auto selEraseTimestamp = "/var/lib/ipmi/sel_erase_time";
constexpr uint8_t firstEntryId = 1;

struct SELPolicyinfo
{
    bool infoFlag;
    bool errorFlag;
    std::string policy;
};

} // namespace ami::ipmi::sel

static constexpr auto logObjPath = "/xyz/openbmc_project/logging";
static constexpr auto logInterface = "xyz.openbmc_project.Logging.Create";
constexpr auto logWatchPath = "/xyz/openbmc_project/logging";
constexpr auto logBasePath = "/xyz/openbmc_project/logging/entry";
constexpr auto logEntryIntf = "xyz.openbmc_project.Logging.Entry";
constexpr auto logDeleteIntf = "xyz.openbmc_project.Object.Delete";
constexpr const char* informationalLevel =
    "xyz.openbmc_project.Logging.Entry.Level.Informational";
constexpr const char* warningLevel =
    "xyz.openbmc_project.Logging.Entry.Level.Warning";
constexpr const char* errorLevel =
    "xyz.openbmc_project.Logging.Entry.Level.Error";
constexpr auto policyLinear =
    "xyz.openbmc_project.Logging.Settings.Policy.Linear";
constexpr auto policyCircular =
    "xyz.openbmc_project.Logging.Settings.Policy.Circular";
enum class eventReading : uint8_t
{
    lowerNonCritGoingLow = 0x00,
    lowerCritGoingLow = 0x02,
    upperNonCritGoingHigh = 0x07,
    upperCritGoingHigh = 0x09
};

#pragma pack(push, 1)
struct GetSDRReq
{
    uint16_t reservationID;
    uint16_t recordID;
    uint8_t offset;
    uint8_t bytesToRead;
};
#pragma pack(pop)

enum class SdrRepositoryInfoOps : uint8_t
{
    allocCommandSupported = 0x1,
    reserveSDRRepositoryCommandSupported = 0x2,
    partialAddSDRSupported = 0x4,
    deleteSDRSupported = 0x8,
    reserved = 0x10,
    modalLSB = 0x20,
    modalMSB = 0x40,
    overflow = 0x80
};

enum class GetFRUAreaAccessType : uint8_t
{
    byte = 0x0,
    words = 0x1
};

enum class SensorUnits : uint8_t
{
    unspecified = 0x0,
    degreesC = 0x1,
    volts = 0x4,
    amps = 0x5,
    watts = 0x6,
    rpm = 0x12,
};

#pragma pack(push, 1)
struct Type12Record
{
    get_sdr::SensorDataRecordHeader header;
    uint8_t targetAddress;
    uint8_t channelNumber;
    uint8_t powerStateNotification;
    uint8_t deviceCapabilities;
    // define reserved bytes explicitly. The uint24_t is silently expanded to
    // uint32_t, which ruins the byte alignment required by this structure.
    uint8_t reserved[3];
    uint8_t entityID;
    uint8_t entityInstance;
    uint8_t oem;
    uint8_t typeLengthCode;
    char name[16];

    Type12Record(uint16_t recordID, uint8_t address, uint8_t chNumber,
                 uint8_t pwrStateNotification, uint8_t capabilities,
                 uint8_t eid, uint8_t entityInst, uint8_t mfrDefined,
                 const std::string& sensorname) :
        targetAddress(address), channelNumber(chNumber),
        powerStateNotification(pwrStateNotification),
        deviceCapabilities(capabilities), reserved{}, entityID(eid),
        entityInstance(entityInst), oem(mfrDefined)
    {
        get_sdr::header::set_record_id(recordID, &header);
        header.sdr_version = ipmiSdrVersion;
        header.record_type = 0x12;
        size_t nameLen = std::min(sensorname.size(), sizeof(name));
        header.record_length =
            sizeof(Type12Record) - sizeof(get_sdr::SensorDataRecordHeader) -
            sizeof(name) + nameLen;
        typeLengthCode = 0xc0 | nameLen;
        std::copy(sensorname.begin(), sensorname.begin() + nameLen, name);
    }
};
#pragma pack(pop)

#pragma pack(push, 1)
struct NMDiscoveryRecord
{
    get_sdr::SensorDataRecordHeader header;
    uint8_t oemID0;
    uint8_t oemID1;
    uint8_t oemID2;
    uint8_t subType;
    uint8_t version;
    uint8_t targetAddress;
    uint8_t channelNumber;
    uint8_t healthEventSensor;
    uint8_t exceptionEventSensor;
    uint8_t operationalCapSensor;
    uint8_t thresholdExceededSensor;
};
#pragma pack(pop)

namespace ipmi
{
namespace storage
{

constexpr const size_t nmDiscoverySDRCount = 1;
constexpr const size_t type12Count = 2;
ipmi::Cc getFruSdrs(ipmi::Context::ptr& ctx, size_t index,
                    get_sdr::SensorDataFruRecord& resp);

ipmi::Cc getFruSdrCount(ipmi::Context::ptr& ctx, size_t& count);

std::vector<uint8_t> getType12SDRs(uint16_t index, uint16_t recordId);
std::vector<uint8_t> getNMDiscoverySDR(uint16_t index, uint16_t recordId);
void initFruConfig();
} // namespace storage
} // namespace ipmi

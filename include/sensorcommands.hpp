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
#include "sdrutils.hpp"

#include <ipmid/api.hpp>

#include <cstdint>

#pragma pack(push, 1)

// specific response codes
constexpr uint8_t ipmiCCParamNotSupported = 0x80;
constexpr uint8_t ipmiCCParamReadOnly = 0x82;

enum class PEFConfParam : uint8_t
{
    setInProgress = 0x0,
    pefControl = 0x1,
    pefActionGlobalControl = 0x2,
    pefStartupDelay = 0x3,
    pefAlertStartupDelay = 0x4,
    numEventFilter = 0x5,
    eventFilterTable = 0x6,
    eventFilterTableData1 = 0x7,
    numAlertPolicyTable = 0x8,
    alertPolicyTable = 0x9,
    systemGUID = 0xA,
    numAlertString = 0xB,
    alertStringKey = 0xC,
    alertString = 0xD,
    numGrpCtlTableEntries = 0xE,
};

static constexpr uint8_t maxEventTblEntry = 0x28;
static constexpr uint8_t maxAlertPolicyEntry = 0x3c;
static constexpr uint8_t ipmiPefParamVer = 0x11;
static constexpr uint8_t eventData0 = 0x00;
static constexpr uint8_t eventData1 = 0x01;
static constexpr uint8_t pefDisable = 0x00;
static constexpr uint8_t tempPefDisable = 0xFE;
static constexpr uint8_t presentCwnValue = 0xff;
static constexpr uint8_t reserveBit1 = 0x80;
static constexpr uint8_t reserveBit2 = 0x40;
static constexpr uint8_t pefControlValue = 0xF0;
static constexpr uint8_t enableFilter = 0x7F;
static constexpr uint8_t numAlertPolicyEntry = 0x07;
static constexpr uint8_t flterConfigRrve1 = 0x1F;
static constexpr uint8_t flterConfigRrve2 = 0x03;

static constexpr const char* pefBus = "xyz.openbmc_project.pef.alert.manager";
static constexpr const char* pefObj = "/xyz/openbmc_project/PefAlertManager";
static constexpr const char* pefDbusIntf =
    "xyz.openbmc_project.pef.configurations";
static constexpr const char* pefConfInfoIntf =
    "xyz.openbmc_project.pef.PEFConfInfo";
constexpr auto PROP_INTF = "org.freedesktop.DBus.Properties";
static constexpr const char* pefPostponeTmrObj =
    "/xyz/openbmc_project/PefAlertManager/ArmPostponeTimer";
static constexpr const char* pefPostponeTmrIface =
    "xyz.openbmc_project.pef.PEFPostponeTimer";
static constexpr const char* pefPostponeCountDownIface =
    "xyz.openbmc_project.pef.CountdownTmr";
static constexpr const char* eventFilterTableObj =
    "/xyz/openbmc_project/PefAlertManager/EventFilterTable/Entry";
static constexpr const char* eventFilterTableIntf =
    "xyz.openbmc_project.pef.EventFilterTable";
static constexpr const char* alertPolicyTableObj =
    "/xyz/openbmc_project/PefAlertManager/AlertPolicyTable/Entry";
static constexpr const char* alertPolicyTableIntf =
    "xyz.openbmc_project.pef.AlertPolicyTable";

struct SensorThresholdResp
{
    uint8_t readable;
    uint8_t lowernc;
    uint8_t lowercritical;
    uint8_t lowernonrecoverable;
    uint8_t uppernc;
    uint8_t uppercritical;
    uint8_t uppernonrecoverable;
};

#pragma pack(pop)

enum class IPMIThresholdRespBits
{
    lowerNonCritical,
    lowerCritical,
    lowerNonRecoverable,
    upperNonCritical,
    upperCritical,
    upperNonRecoverable
};

enum class IPMISensorReadingByte2 : uint8_t
{
    eventMessagesEnable = (1 << 7),
    sensorScanningEnable = (1 << 6),
    readingStateUnavailable = (1 << 5),
};

enum class IPMISensorReadingByte3 : uint8_t
{
    upperNonRecoverable = (1 << 5),
    upperCritical = (1 << 4),
    upperNonCritical = (1 << 3),
    lowerNonRecoverable = (1 << 2),
    lowerCritical = (1 << 1),
    lowerNonCritical = (1 << 0),
    presenceDetected = (1 << 0),
    procPresenceDetected = (1 << 7),
    watchdog2None = (1 << 0),
    watchdog2HardReset = (1 << 1),
    watchdog2PowerOff = (1 << 2),
    watchdog2PowerCycle = (1 << 3),
};

enum class IPMISensorEventEnableByte2 : uint8_t
{
    eventMessagesEnable = (1 << 7),
    sensorScanningEnable = (1 << 6),
};

enum class IPMISensorEventEnableThresholds : uint8_t
{
    nonRecoverableThreshold = (1 << 6),
    criticalThreshold = (1 << 5),
    nonCriticalThreshold = (1 << 4),
    upperNonRecoverableGoingHigh = (1 << 3),
    upperNonRecoverableGoingLow = (1 << 2),
    upperCriticalGoingHigh = (1 << 1),
    upperCriticalGoingLow = (1 << 0),
    upperNonCriticalGoingHigh = (1 << 7),
    upperNonCriticalGoingLow = (1 << 6),
    lowerNonRecoverableGoingHigh = (1 << 5),
    lowerNonRecoverableGoingLow = (1 << 4),
    lowerCriticalGoingHigh = (1 << 3),
    lowerCriticalGoingLow = (1 << 2),
    lowerNonCriticalGoingHigh = (1 << 1),
    lowerNonCriticalGoingLow = (1 << 0),
};

enum class IPMIGetSensorEventEnableThresholds : uint8_t
{
    lowerNonCriticalGoingLow = 0,
    lowerNonCriticalGoingHigh = 1,
    lowerCriticalGoingLow = 2,
    lowerCriticalGoingHigh = 3,
    lowerNonRecoverableGoingLow = 4,
    lowerNonRecoverableGoingHigh = 5,
    upperNonCriticalGoingLow = 6,
    upperNonCriticalGoingHigh = 7,
    upperCriticalGoingLow = 8,
    upperCriticalGoingHigh = 9,
    upperNonRecoverableGoingLow = 10,
    upperNonRecoverableGoingHigh = 11,
};

enum class IPMINetfnSensorCmds : ipmi_cmd_t
{
    ipmiCmdGetDeviceSDRInfo = 0x20,
    ipmiCmdGetDeviceSDR = 0x21,
    ipmiCmdReserveDeviceSDRRepo = 0x22,
    ipmiCmdSetSensorThreshold = 0x26,
    ipmiCmdGetSensorThreshold = 0x27,
    ipmiCmdGetSensorEventEnable = 0x29,
    ipmiCmdGetSensorEventStatus = 0x2B,
    ipmiCmdGetSensorReading = 0x2D,
    ipmiCmdGetSensorType = 0x2F,
    ipmiCmdSetSensorReadingAndEventStatus = 0x30,
};

namespace sensor
{
/**
 * @brief Retrieve the number of sensors that are not included in the list of
 * sensors published via D-Bus
 *
 * @param[in]: ctx: the pointer to the D-Bus context
 * @return: The number of additional sensors separate from those published
 * dynamically on D-Bus
 */
size_t getOtherSensorsCount(ipmi::Context::ptr ctx);

/**
 * @brief Retrieve the record data for the sensors not published via D-Bus
 *
 * @param[in]: ctx: the pointer to the D-Bus context
 * @param[in]: recordID: the integer index for the sensor to retrieve
 * @param[out]: SDR data for the indexed sensor
 * @return: 0: success
 *          negative number: error condition
 */
int getOtherSensorsDataRecord(ipmi::Context::ptr ctx, uint16_t recordID,
                              std::vector<uint8_t>& recordData);
} // namespace sensor

namespace ipmi
{

uint16_t getNumberOfSensors();

SensorSubTree& getSensorTree();

ipmi_ret_t getSensorConnection(ipmi::Context::ptr ctx, uint8_t sensnum,
                               std::string& connection, std::string& path,
                               std::vector<std::string>* interfaces = nullptr);

struct IPMIThresholds
{
    std::optional<uint8_t> warningLow;
    std::optional<uint8_t> warningHigh;
    std::optional<uint8_t> criticalLow;
    std::optional<uint8_t> criticalHigh;
    std::optional<uint8_t> nonRecoverableLow;
    std::optional<uint8_t> nonRecoverableHigh;
};

} // namespace ipmi

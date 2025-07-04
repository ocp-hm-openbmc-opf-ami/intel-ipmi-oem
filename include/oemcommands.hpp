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

#pragma once

#include <ipmid/api-types.hpp>
#include <user_channel/user_layer.hpp>

namespace ipmi
{
namespace intel
{

static constexpr NetFn netFnGeneral = netFnOemOne;
static constexpr NetFn netFnPlatform = netFnOemTwo;
static constexpr NetFn netFnApp = netFnOemEight;

constexpr auto netFnOem = 0x3C;
constexpr auto netGroupExt = 0x52;

namespace general
{
static constexpr Cmd cmdGetBmcVersionString = 0x01;
static constexpr Cmd cmdRestoreConfiguration = 0x02;
static constexpr Cmd cmdGetSmSignal = 0x14;
static constexpr Cmd cmdSetSmSignal = 0x15;
static constexpr Cmd cmdSetBIOSID = 0x26;
static constexpr Cmd cmdGetOEMDeviceInfo = 0x27;
static constexpr Cmd cmdSetColdRedundancyConfig = 0x2d;
static constexpr Cmd cmdGetColdRedundancyConfig = 0x2e;
static constexpr Cmd cmdGetAICSlotFRUIDSlotPosRecords = 0x31;
static constexpr Cmd cmdGetMultiNodeRole = 0x33;
static constexpr Cmd cmdGetMultiNodeId = 0x36;
static constexpr Cmd cmdSetSystemGUID = 0x41;
static constexpr Cmd cmdDisableBMCSystemReset = 0x42;
static constexpr Cmd cmdGetBMCResetDisables = 0x43;
static constexpr Cmd cmdSendEmbeddedFWUpdStatus = 0x44;
static constexpr Cmd cmdSlotI2CControllerWriteRead = 0x52;
static constexpr Cmd cmdSetPowerRestoreDelay = 0x54;
static constexpr Cmd cmdGetPowerRestoreDelay = 0x55;
static constexpr Cmd cmdSetFaultIndication = 0x57;
static constexpr Cmd cmdSetOEMUser2Activation = 0x5A;
static constexpr Cmd cmdSetSpecialUserPassword = 0x5F;
static constexpr Cmd cmdSetShutdownPolicy = 0x60;
static constexpr Cmd cmdGetShutdownPolicy = 0x62;
static constexpr Cmd cmdGetMultiNodePresence = 0x63;
static constexpr Cmd cmdGetBufferSize = 0x66;
static constexpr Cmd cmdSetFanConfig = 0x89;
static constexpr Cmd cmdGetFanConfig = 0x8a;
static constexpr Cmd cmdSetFanSpeedOffset = 0x8c;
static constexpr Cmd cmdGetFanSpeedOffset = 0x8d;
static constexpr Cmd cmdSetDimmOffset = 0x8e;
static constexpr Cmd cmdGetDimmOffset = 0x8f;
static constexpr Cmd cmdSetFscParameter = 0x90;
static constexpr Cmd cmdGetFscParameter = 0x91;
static constexpr Cmd cmdGetChassisIdentifier = 0x92;
static constexpr Cmd cmdReadBaseBoardProductId = 0x93;
static constexpr Cmd cmdGetProcessorErrConfig = 0x9A;
static constexpr Cmd cmdSetProcessorErrConfig = 0x9B;
static constexpr Cmd cmdSetManufacturingData = 0xA1;
static constexpr Cmd cmdGetManufacturingData = 0xA2;
static constexpr Cmd cmdSetFITcLayout = 0xA3;
static constexpr Cmd cmdMTMBMCFeatureControl = 0xA4;
static constexpr Cmd cmdGetLEDStatus = 0xB0;
static constexpr Cmd cmdControlBmcServices = 0xB1;
static constexpr Cmd cmdGetBmcServiceStatus = 0xB2;
static constexpr Cmd cmdGetSecurityMode = 0xB3;
static constexpr Cmd cmdSetSecurityMode = 0xB4;
static constexpr Cmd cmdMtmKeepAlive = 0xB5;
static constexpr Cmd cmdOEMGetReading = 0xE2;
static constexpr Cmd cmdOEMSetSmtpConfig = 0xE3;
static constexpr Cmd cmdOEMGetSmtpConfig = 0xE4;
static constexpr Cmd cmdSetBIOSCap = 0xD3;
static constexpr Cmd cmdGetBIOSCap = 0xD4;
static constexpr Cmd cmdSetPayload = 0xD5;
static constexpr Cmd cmdGetPayload = 0xD6;
static constexpr Cmd cmdSetBIOSPwdHashInfo = 0xD7;
static constexpr Cmd cmdGetBIOSPwdHash = 0xD8;
static constexpr Cmd cmdGetNmiStatus = 0xE5;
static constexpr Cmd cmdSetEfiBootOptions = 0xEA;
static constexpr Cmd cmdGetEfiBootOptions = 0xEB;
static constexpr Cmd cmdSetNmiStatus = 0xED;
static constexpr Cmd cmdGetPSUVersion = 0xEF;
static constexpr Cmd cmdReadCertficate = 0x1C;
} // namespace general

namespace platform
{
static constexpr Cmd cmdCfgHostSerialPortSpeed = 0x90;
static constexpr Cmd cmdClearCMOS = 0x91;
} // namespace platform

namespace app
{
static constexpr Cmd cmdMdrStatus = 0x20;
static constexpr Cmd cmdMdrComplete = 0x21;
static constexpr Cmd cmdMdrEvent = 0x22;
static constexpr Cmd cmdMdrRead = 0x23;
static constexpr Cmd cmdMdrWrite = 0x24;
static constexpr Cmd cmdMdrLock = 0x25;

constexpr auto cmdGetUsbDescription = 0x30;
constexpr auto cmdGetUsbSerialNum = 0x31;
constexpr auto cmdGetRedfishHostName = 0x32;
constexpr auto cmdGetipmiChannelRfHi = 0x33;
constexpr auto cmdGetBootStrapAcc = 0x02;

static constexpr Cmd cmdMdrIIAgentStatus = 0x30;
static constexpr Cmd cmdMdrIIGetDir = 0x31;
static constexpr Cmd cmdMdrIIGetDataInfo = 0x32;
static constexpr Cmd cmdMdrIILockData = 0x33;
static constexpr Cmd cmdMdrIIUnlockData = 0X34;
static constexpr Cmd cmdMdrIIGetDataBlock = 0x35;
static constexpr Cmd cmdMdrIISendDir = 0x38;
static constexpr Cmd cmdMdrIISendDataInfoOffer = 0x39;
static constexpr Cmd cmdMdrIISendDataInfo = 0x3a;
static constexpr Cmd cmdMdrIIDataStart = 0x3b;
static constexpr Cmd cmdMdrIIDataDone = 0x3c;
static constexpr Cmd cmdMdrIISendDataBlock = 0x3d;
static constexpr Cmd cmdSlotIpmb = 0x51;
static constexpr Cmd cmdPFRMailboxRead = 0x84;
} // namespace app

namespace misc
{
constexpr auto cmdGetOEMVersion = 0x01;
constexpr auto cmdGetFwBootupSlot = 0x03;
constexpr auto cmdSoftPowerCycle = 0x04;
constexpr auto cmdGetBMCBootComplete = 0x05;
constexpr auto cmdSMBPBIPassthrough = 0x09;
constexpr auto cmdSMBPBIPassthroughExtended = 0x0A;
constexpr auto cmdGetPSUInventory = 0x0E;
constexpr auto cmdGetDeviceFirmwareVersion = 0x0F;
constexpr auto cmdSensorScanEnable = 0x85;
constexpr auto cmdSetSSDLed = 0x63;
constexpr auto cmdGetSSDLed = 0x64;
constexpr auto cmdGetLedStatus = 0x65;
constexpr auto cmdGetWpStatus = 0x8A;
constexpr auto cmdSetWpStatus = 0x8B;
constexpr auto cmdGetPsuPower = 0x78;
constexpr auto cmdGetBiosBootupImage = 0x1E;
constexpr auto cmdGetBiosConfig = 0x21;
constexpr auto cmdGetBiosNextImage = 0x22;
constexpr auto cmdSetBiosNextImage = 0x23;
constexpr auto cmdGetBiosVerions = 0x24;
constexpr auto cmdSetBiosConfig = 0x25;
constexpr auto cmdGetUsbDescription = 0x30;
constexpr auto cmdGetUsbSerialNum = 0x31;
constexpr auto cmdGetRedfishHostName = 0x32;
constexpr auto cmdGetipmiChannelRfHi = 0x33;
constexpr auto cmdGetRedfishServiceUuid = 0x34;
constexpr auto cmdGetRedfishServicePort = 0x35;
constexpr auto cmdGetManagerCertFingerPrint = 0x01;
constexpr auto cmdGetBootStrapAcc = 0x02;
constexpr auto cmdGetMaxPMaxQConfiguration = 0x90;
constexpr auto cmdSetMaxPMaxQConfiguration = 0x91;

constexpr auto getFirmwareVersionDeviceMBFPGA = 0x00;
constexpr auto getFirmwareVersionDeviceGBFPGA = 0x01;
constexpr auto getFirmwareVersionDevicePSU0 = 0x02;
constexpr auto getFirmwareVersionDevicePSU1 = 0x03;
constexpr auto getFirmwareVersionDevicePSU2 = 0x04;
constexpr auto getFirmwareVersionDevicePSU3 = 0x05;
constexpr auto getFirmwareVersionDevicePSU4 = 0x06;
constexpr auto getFirmwareVersionDevicePSU5 = 0x07;
constexpr auto getFirmwareVersionDeviceMIDFPGA = 0x08;
constexpr auto getFirmwareVersionDeviceCEC = 0x09;
constexpr auto getFirmwareVersionDeviceFPGACEC = 0x0A;
constexpr auto getFirmwareVersionDevicePEXSwitch0 = 0x10;
constexpr auto getFirmwareVersionDevicePEXSwitch1 = 0x11;
constexpr auto getFirmwareVersionDevicePEXSwitch2 = 0x12;
constexpr auto getFirmwareVersionDevicePEXSwitch3 = 0x13;
constexpr auto getFirmwareVersionDeviceBMCActive = 0x20;
constexpr auto getFirmwareVersionDeviceBMCInactive = 0x21;

constexpr auto getWPTypePEX = 0x00;
constexpr auto getWPTypeFRU = 0x01;

constexpr auto getWPIdPexSW0 = 0x00;
constexpr auto getWPIdPexSW1 = 0x01;
constexpr auto getWPIdPexSW2 = 0x02;
constexpr auto getWPIdPexSW3 = 0x03;

constexpr auto getWPIdMB = 0x00;
constexpr auto getWPIdMid = 0x01;
constexpr auto getWPIdIOEL = 0x02;
constexpr auto getWpIdIOER = 0x03;
constexpr auto getWpIdPDB = 0x04;
constexpr auto getWpIdGB = 0x05;
constexpr auto getWPIdM2 = 0x06;
constexpr auto getWpIdSW = 0x07;

constexpr auto getSSDLedTypeReadyMove = 0x30;
constexpr auto getSSDLedTypeActivity = 0x31;
constexpr auto getSSDLedTypeFault = 0x32;

constexpr auto getSSDLedNLed = 8;

constexpr auto getLedStatusPowerLed = 0x00;
constexpr auto getLedStatusFaultLed = 0x01;
constexpr auto getLedStatusMotherBoardLed = 0x10;

constexpr auto biosConfigTypeNetwork = 0x01;
constexpr auto biosConfigTypeRedFish = 0x02;

constexpr auto getMaxPMaxQConfigurationMode = 0x00;
constexpr auto getMaxPMaxQConfigurationCurrentPowerLimit = 0x01;
constexpr auto getMaxPMaxQConfigurationCurrentPowerLimitP = 0x02;
constexpr auto getMaxPMaxQConfigurationCurrentPowerLimitQ = 0x03;
constexpr auto getMaxPMaxQConfigurationCurrentPowerLimitMax = 0x04;
constexpr auto getMaxPMaxQConfigurationCurrentPowerLimitMin = 0x05;
constexpr auto getMaxPMaxQConfigurationRestOfSytemPower = 0x06;

constexpr auto setMaxPMaxQConfigurationMode = 0x00;
constexpr auto setMaxPMaxQConfigurationCurrentPowerLimit = 0x01;

constexpr auto staticMode = 0x01;
constexpr auto maximumPerformanceMode = 0x01;
constexpr auto powerSavingMode = 0x02;
constexpr auto OemMode = 0x03;

constexpr uint8_t getMaskdata(int data, int position)
{
    return (data >> position * 8) & 0xff;
}

} // namespace misc

} // namespace intel

namespace ami
{
static constexpr NetFn netFnGeneral = netFnOemTwo;

namespace general
{
static constexpr Cmd cmdOEMSetFirewallConfiguration = 0x76;
static constexpr Cmd cmdOEMGetFirewallConfiguration = 0x77;
static constexpr Cmd cmdOEMGetSELPolicy = 0x7E;
static constexpr Cmd cmdOEMSetSELPolicy = 0x7F;
static constexpr Cmd cmdOEMGetKCSStatus = 0x3E;
static constexpr Cmd cmdOEMSetKCSStatus = 0x3F;
static constexpr Cmd cmdOEMCancelTask = 0xB1;
static constexpr Cmd cmdOEMEnDisPowerSaveMode = 0xAA;
static constexpr Cmd cmdOEMGetPowerSaveMode = 0xAB;
static constexpr Cmd cmdOEMTriggerScreenshot = 0xD2;
static constexpr Cmd cmdOEMSetSNMPStatus = 0xC1;
static constexpr Cmd cmdOEMGetSNMPstatus = 0xC2;
static constexpr Cmd cmdOEMSetSessionTimeout = 0xd3;
static constexpr Cmd cmdOEMGetSessionTimeout = 0xd4;
static constexpr Cmd cmdSetBmcServiceStatus = 0xE1;
static constexpr Cmd cmdGetBmcServiceStatus = 0xE2;
static constexpr Cmd cmdSetBmcServicePortValue = 0xE3;
static constexpr Cmd cmdGetBmcServicePortValue = 0xE4;
static constexpr Cmd cmdOEMSetExtlogConfigs = 0xE5;
static constexpr Cmd cmdOEMGetExtlogConfigs = 0xE6;
static constexpr Cmd cmdOEMClearSessionInfo = 0xd5;
static constexpr Cmd cmdGetBiosPostCode = 0xD1;
constexpr auto cmdGetBiosPostCodeToIpmiMaxSize = 945;
static constexpr Cmd cmdOEMGetTimezone = 0x9E;
static constexpr Cmd cmdOEMSetTimezone = 0x9F;

namespace network
{
static constexpr const char* phosphorNetworkService =
    "xyz.openbmc_project.Network";
static constexpr const char* firewallConfigurationObj =
    "/xyz/openbmc_project/network/firewall";
static constexpr const char* firewallConfigurationIntf =
    "xyz.openbmc_project.Network.FirewallConfiguration";

enum class FirewallFlags : uint8_t
{
    PROTOCOL = 0x01,
    IP = 0x02,
    PORT = 0x04,
    MAC = 0x08,
    TIMEOUT = 0x10,
};

enum class SetFirewallOEMParam : uint16_t
{
    PARAM_TARGET,
    PARAM_PROTOCOL,
    PARAM_START_SOURCE_IP_ADDR,
    PARAM_END_SOURCE_IP_ADDR,
    PARAM_START_PORT,
    PARAM_END_PORT,
    PARAM_SOURCE_MAC_ADDR,
    PARAM_START_TIME,
    PARAM_END_TIME,
    PARAM_APPLY,
    PARAM_FLUSH,
};

enum class GetFirewallOEMParam : uint16_t
{
    PARAM_RULE_NUMBER,
    PARAM_IPV4_RULE,
    PARAM_IPV6_RULE,
};
} // namespace network
} // namespace general
} // namespace ami
} // namespace ipmi

// FIXME: put these in the cpp files that use them
enum class IPMIIntelOEMReturnCodes
{
    ipmiCCPayloadActive = 0x80,
    ipmiCCInvalidPCIESlotID = 0x80,
    ipmiCCParameterNotSupported = 0x80,
    ipmiCCPayloadAlreadyDeactivated = 0x80,
    ipmiCCSetInProcess = 0x81,
    ipmiCCPayloadDisable = 0x81,
    ipmiCCLostArbitration = 0x81,
    ipmiCCInvalidCablePortIndex = 0x81,
    ipmiCCHealthStatusNotAvailable = 0x81,
    ipmiCCBusError = 0x82,
    ipmiCCReadOnly = 0x82,
    ipmiCCWriteOnly = 0x82,
    ipmiCCNoCablePresent = 0x82,
    ipmiCCDataCollectionInProgress = 0x82,
    ipmiCCPayloadActivationLimitReached = 0x82,
    ipmiCCNACKOnWrite = 0x83,
    ipmiCCDataCollectionFailed = 0x83,
    ipmiCCCanNotActivateWithEncrption = 0x83,
    ipmiCCCanNotActivateWithoutEncryption = 0x84,
    ipmiCCInvalidChecksum = 0x85,
    ipmiCCNoCabledPCIEPortsAvailable = 0xC2,

};

enum class IPMIReturnCodeExt
{
    ipmiCCInvalidLUN = 0xC2,
    ipmiCCTimeout = 0xC3,
    ipmiCCStorageLeak = 0xC4,
    ipmiCCRequestDataTruncated = 0xC6,
    ipmiCCRequestDataFieldLengthLimitExceeded = 0xC8,
    ipmiCCCanNotReturnNumberOfRequestedDataBytes = 0xCA,
    ipmiCCRequestSensorDataRecordNotFound = 0xCB,
    ipmiCCDestinationUnavailable = 0xD3,
    ipmiCCParamterNotSupportInPresentState = 0xD5,
};

static constexpr const uint8_t maxBIOSIDLength = 0xFF;
static constexpr const uint8_t maxCPUNum = 4;
static constexpr const char* biosActiveObjPath =
    "/xyz/openbmc_project/software/bios_active";
static constexpr const char* biosVersionIntf =
    "xyz.openbmc_project.Software.Version";
static constexpr const char* biosVersionProp = "Version";

static constexpr const char* powerRestoreDelayObjPath =
    "/xyz/openbmc_project/control/host0/power_restore_policy";
static constexpr const char* powerRestoreDelayIntf =
    "xyz.openbmc_project.Control.Power.RestorePolicy";
static constexpr const char* powerRestoreDelayProp = "PowerRestoreDelay";
static constexpr const char* processorErrConfigObjPath =
    "/xyz/openbmc_project/control/processor_error_config";
static constexpr const char* processorErrConfigIntf =
    "xyz.openbmc_project.Control.Processor.ErrConfig";
static constexpr const char* bmcResetDisablesPath =
    "/xyz/openbmc_project/control/bmc_reset_disables";
static constexpr const char* bmcResetDisablesIntf =
    "xyz.openbmc_project.Control.ResetDisables";

static constexpr const char* identifyLEDObjPath =
    "/xyz/openbmc_project/led/physical/identify";
static constexpr const char* ledIntf = "xyz.openbmc_project.Led.Physical";
static constexpr const char* statusAmberObjPath =
    "/xyz/openbmc_project/led/physical/status_amber";
static constexpr const char* statusGreenObjPath =
    "/xyz/openbmc_project/led/physical/status_green";

static constexpr const uint8_t noShutdownOnOCOT = 0;
static constexpr const uint8_t shutdownOnOCOT = 1;
static constexpr const uint8_t noShutdownPolicySupported = 0;
static constexpr const uint8_t shutdownPolicySupported = 1;
static constexpr const char* oemShutdownPolicyIntf =
    "com.intel.Control.OCOTShutdownPolicy";
static constexpr const char* oemShutdownPolicyObjPath =
    "/com/intel/control/ocotshutdown_policy_config";
static constexpr const char* oemShutdownPolicyObjPathProp = "OCOTPolicy";

static constexpr const char* fwGetEnvCmd = "/sbin/fw_printenv";
static constexpr const char* fwSetEnvCmd = "/sbin/fw_setenv";
static constexpr const char* fwHostSerailCfgEnvName = "hostserialcfg";

constexpr const char* settingsBusName = "xyz.openbmc_project.Settings";

static constexpr const uint8_t getHostSerialCfgCmd = 0;
static constexpr const uint8_t setHostSerialCfgCmd = 1;

static constexpr const char* smtpclient = "xyz.openbmc_project.mail";
static constexpr const char* smtpObj = "/xyz/openbmc_project/mail/alert";
static constexpr const char* smtpIntf = "xyz.openbmc_project.mail.alert";
static constexpr const char* smtpPrimaryIntf =
    "xyz.openbmc_project.mail.alert.primary";
static constexpr const char* smtpSecondaryIntf =
    "xyz.openbmc_project.mail.alert.secondary";

static constexpr const char* pefBus = "xyz.openbmc_project.pef.alert.manager";
static constexpr const char* pefObj = "/xyz/openbmc_project/PefAlertManager";
static constexpr const char* pefConfInfoIntf =
    "xyz.openbmc_project.pef.PEFConfInfo";

static constexpr const char* loggingSettingIntf =
    "xyz.openbmc_project.Logging.Settings";
static constexpr const char* loggingSettingObjPath =
    "/xyz/openbmc_project/logging/settings";

/*Manuall Trigger Screen Shot via d-bus obj*/
static constexpr const char* TriggerScreenShotService =
    "xyz.openbmc_project.Kvm";
static constexpr const char* TriggerScreenShotObjPath =
    "/xyz/openbmc_project/Kvm";
static constexpr const char* TriggerScreenShotIntf =
    "xyz.openbmc_project.Kvm.Screenshot";

static constexpr const char* CurrentHostState =
    "xyz.openbmc_project.State.Host.HostState.Running";

/*Serice Config Manager D-bus details*/
static constexpr const char* serviceManagerService =
    "xyz.openbmc_project.Control.Service.Manager";
static constexpr const char* serviceMgrKvmObjPath =
    "/xyz/openbmc_project/control/service/start_2dipkvm";
static constexpr const char* serviceConfigInterface =
    "xyz.openbmc_project.Control.Service.Attributes";

static constexpr const char* extlogconfigIntf =
    "xyz.openbmc_project.Extlog.ExtlogConfigs";
static constexpr const char* extlogconfigObjPath =
    "/xyz/openbmc_project/Extlog/ExtlogConfigs";

// session timeout in seconds
static constexpr const uint64_t minSessionTimeOut = 30;
static constexpr const uint64_t maxSessionTimeOut = 86400;

// control BMC services
static constexpr uint8_t webServiceBitPos = 0;
static constexpr uint8_t sshServiceBitPos = 1;
static constexpr uint8_t ipmbServiceBitPos = 2;
static constexpr uint8_t solS0ServiceBitPos = 3;
static constexpr uint8_t solS1ServiceBitPos = 4;
static constexpr uint8_t solS2ServiceBitPos = 5;
static constexpr uint8_t solS3ServiceBitPos = 6;
static constexpr uint8_t ipmiKcsBridge3ServiceBitPos = 7;
static constexpr uint8_t ipmiKcsBridge4ServiceBitPos = 8;
static constexpr uint8_t rmcpBond0ServiceBitPos = 9;
static constexpr uint8_t rmcpEth0ServiceBitPos = 10;
static constexpr uint8_t rmcpEth1ServiceBitPos = 11;
static constexpr uint8_t rmcpUsb0ServiceBitPos = 12;
static constexpr uint8_t kvmServiceBitPos = 13;
static constexpr uint8_t virtualMediaServiceBitPos = 14;

static constexpr uint16_t maxServiceBit = 0x7FFF;
static constexpr uint16_t maxPortValue = 0xFFFF;

static constexpr std::array<std::pair<uint8_t, const char*>, 15> bmcService = {{
    // {bit position for service, service name}
    {webServiceBitPos, "bmcweb"},
    {sshServiceBitPos, "dropbear"},
    {ipmbServiceBitPos, "ipmb"},
    {solS0ServiceBitPos, "obmc_2dconsole_40ttyS0"},
    {solS1ServiceBitPos, "obmc_2dconsole_40ttyS1"},
    {solS2ServiceBitPos, "obmc_2dconsole_40ttyS2"},
    {solS3ServiceBitPos, "obmc_2dconsole_40ttyS3"},
    {ipmiKcsBridge3ServiceBitPos, "phosphor_2dipmi_2dkcs_40ipmi_kcs3"},
    {ipmiKcsBridge4ServiceBitPos, "phosphor_2dipmi_2dkcs_40ipmi_kcs4"},
    {rmcpBond0ServiceBitPos, "phosphor_2dipmi_2dnet_40bond0"},
    {rmcpEth0ServiceBitPos, "phosphor_2dipmi_2dnet_40eth0"},
    {rmcpEth1ServiceBitPos, "phosphor_2dipmi_2dnet_40eth1"},
    {rmcpUsb0ServiceBitPos, "phosphor_2dipmi_2dnet_40usb0"},
    {kvmServiceBitPos, "start_2dipkvm"},
    {virtualMediaServiceBitPos, "xyz_2eopenbmc_project_2eVirtualMedia"},
}};

static constexpr const char* objectManagerIntf =
    "org.freedesktop.DBus.ObjectManager";
static constexpr const char* dBusPropIntf = "org.freedesktop.DBus.Properties";
static constexpr const char* serviceConfigBasePath =
    "/xyz/openbmc_project/control/service";
static constexpr const char* serviceConfigAttrIntf =
    "xyz.openbmc_project.Control.Service.Attributes";
static constexpr const char* socketConfigAttrIntf =
    "xyz.openbmc_project.Control.Service.SocketAttributes";
static constexpr const char* getMgdObjMethod = "GetManagedObjects";
static constexpr const char* propMasked = "Masked";
static constexpr const char* propPort = "Port";

/* Session Management D-bus details*/
static constexpr const char* sessionManagerService =
    "xyz.openbmc_project.SessionManager";
static constexpr const char* sessionManagerObjPath =
    "/xyz/openbmc_project/SessionManager";
static constexpr const char* sessionManagerIntf =
    "xyz.openbmc_project.SessionManager";

// parameters:
// 0: host serial port 1 and 2 normal speed
// 1: host serial port 1 high spend, port 2 normal speed
// 2: host serial port 1 normal spend, port 2 high speed
// 3: host serial port 1 and 2 high speed
static constexpr const uint8_t HostSerialCfgParamMax = 3;
static constexpr uint8_t ipmiDefaultUserId = 2;

static constexpr const uint8_t selEvtTargetMask = 0xF0;
static constexpr const uint8_t selEvtTargetShift = 4;

static constexpr const uint8_t targetInstanceMask = 0x0E;
static constexpr const uint8_t targetInstanceShift = 1;

static constexpr const uint8_t readCRC32AndSize = 0x01;
static constexpr const uint8_t readCACertFile = 0x02;

// SMTP Config parameters:
static constexpr const uint8_t min_recipient = 0x01;
static constexpr const uint8_t max_recipient = 0x04;

enum class ServerType
{
    SMTP_PRIMARY,
    SMTP_SECONDARY,
};

enum class IPMINetfnIntelOEMAppCmd
{
    mdrStatus = 0x20,
    mdrComplete = 0x21,
    mdrEvent = 0x22,
    mdrRead = 0x23,
    mdrWrite = 0x24,
    mdrLock = 0x25,
    mdr2AgentStatus = 0x30,
    mdr2GetDir = 0x31,
    mdr2GetDataInfo = 0x32,
    mdr2LockData = 0x33,
    mdr2UnlockData = 0x34,
    mdr2GetDataBlock = 0x35,
    mdr2SendDir = 0x38,
    mdr2SendDataInfoOffer = 0x39,
    mdr2SendDataInfo = 0x3a,
    mdr2DataStart = 0x3b,
    mdr2DataDone = 0x3c,
    mdr2SendDataBlock = 0x3d,
};

enum class OEMDevEntityType
{
    biosId,
    devVer,
    sdrVer,
};

enum class FWUpdateTarget : uint8_t
{
    targetBMC = 0x0,
    targetBIOS = 0x1,
    targetME = 0x2,
    targetOEMEWS = 0x4,
};

enum class CPUStatus
{
    disabled = 0x0,
    enabled = 0x1,
    notPresent = 0x3,
};

#pragma pack(push, 1)
struct GUIDData
{
    uint8_t node1;
    uint8_t node2;
    uint8_t node3;
    uint8_t node4;
    uint8_t node5;
    uint8_t node6;
    uint8_t clock1;
    uint8_t clock2;
    uint8_t timeHigh1;
    uint8_t timeHigh2;
    uint8_t timeMid1;
    uint8_t timeMid2;
    uint8_t timeLow1;
    uint8_t timeLow2;
    uint8_t timeLow3;
    uint8_t timeLow4;
};

struct DeviceInfo
{
    uint8_t biosIDLength;
    uint8_t biosId[maxBIOSIDLength];
};

struct SetPowerRestoreDelayReq
{
    uint8_t byteMSB;
    uint8_t byteLSB;
};

struct GetPowerRestoreDelayRes
{
    uint8_t byteMSB;
    uint8_t byteLSB;
};

struct GetOemDeviceInfoRes
{
    uint8_t resDatalen;
    uint8_t data[maxBIOSIDLength];
};

struct GetOEMShutdownPolicyRes
{
    uint8_t policy;
    uint8_t policySupport;
};

struct CfgHostSerialReq
{
    uint8_t command;
    uint8_t parameter;
};
#pragma pack(pop)

//
// Fault type enumeration
//
enum class RemoteFaultType
{
    fan,         // 0
    temperature, // 1
    power,       // 2
    driveslot,   // 3
    software,    // 4
    memory,      // 5
    max = 6      // 6
};

// Enumeration for remote fault states as required by the HSC
//
enum class RemoteFaultState
{
    // fault indicators
    fanLEDs,
    cpu1DimmLeds,
    cpu2DimmLeds,
    cpu3DimmLeds,
    cpu4DimmLeds,
    maxFaultState,
};

enum class DimmFaultType
{
    cpu1cpu2Dimm,
    cpu3cpu4Dimm,
    maxFaultGroup,
};

enum class setFscParamFlags : uint8_t
{
    tcontrol = 0x1,
    pwmOffset = 0x2,
    maxPwm = 0x3,
    cfm = 0x4
};

enum class dimmOffsetTypes : uint8_t
{
    staticCltt = 0x0,
    dimmPower = 0x2
};

enum class smtpSetting : uint8_t
{
    authentication = 0x1,
    enable = 0x2,
    ipAdd = 0x3,
    passWord = 0x4,
    port = 0x5,
    recMailId = 0x6,
    senderMailId = 0x7,
    tlsEnable = 0x8,
    userName = 0x9,
    ipAddv6 = 0x0a,

};

// FIXME: this stuff needs to be rewritten
enum IPMI_INTEL_OEM_RETURN_CODES
{
    IPMI_CC_OEM_PAYLOAD_ACTIVE = 0x80,
    IPMI_CC_OEM_INVALID_PCIE_SLOTID = 0x80,
    IPMI_CC_OEM_PARAMETER_NOT_SUPPORTED = 0x80,
    IPMI_CC_OEM_PAYLOAD_ALREADY_DEACTIVATED = 0x80,
    IPMI_CC_OEM_SET_IN_PROCESS = 0x81,
    IPMI_CC_OEM_PAYLOAD_DISABLE = 0x81,
    IPMI_CC_OEM_LOST_ARBITRATION = 0x81,
    IPMI_CC_OEM_INVALID_CABLE_PORT_INDEX = 0x81,
    IPMI_CC_OEM_HEALTH_STATUS_NOT_AVAILABLE = 0x81,
    IPMI_CC_OEM_BUS_ERROR = 0x82,
    IPMI_CC_OEM_READ_ONLY = 0x82,
    IPMI_CC_OEM_WRITE_ONLY = 0x82,
    IPMI_CC_OEM_NO_CABLE_PRESENT = 0x82,
    IPMI_CC_OEM_DATA_COLLECTION_IN_PROGRESS = 0x82,
    IPMI_CC_OEM_PAYLOAD_ACTIVATION_LIMIT_REACH = 0x82,
    IPMI_CC_OEM_NACK_ON_WRITE = 0x83,
    IPMI_CC_OEM_DATA_COLLECTION_FAILED = 0x83,
    IPMI_CC_OEM_CAN_NOT_ACTIVATE_WITH_ENCRYPTION = 0x83,
    IPMI_CC_OEM_CAN_NOT_ACTIVATE_WITHOUT_ENCRYPTION = 0x84,
    IPMI_CC_OEM_INVALID_CHECKSUM = 0x85,
    IPMI_CC_OEM_NO_CABLED_PCIE_PORTS_AVAILABLE = 0xC2,
};

enum IPMI_RETURN_CODE_EXT
{
    IPMI_CC_INVALID_LUN = 0xC2,
    IPMI_CC_STORGE_LEAK = 0xC4,
    IPMI_CC_REQUEST_DATA_TRUNCATED = 0xC6,
    IPMI_CC_REQUEST_DATA_FIELD_LENGTH_LIMIT_EXCEEDED = 0xC8,
    IPMI_CC_CANNOT_RETURN_NUMBER_OF_REQUESTED_DATA_BYTES = 0xCA,
    IPMI_CC_REQUEST_SENSOR_DATA_RECORD_NOT_FOUND = 0xCB,
    IPMI_CC_DESTINATION_UNAVAILABLE = 0xD3,
    IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE = 0xD5,
};

static constexpr const uint32_t CrcLookUpTable[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
    0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
    0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
    0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
    0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
    0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,

    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F,
    0x9FBFE4A5, 0xE8B8D433, 0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
    0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162,
    0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49,
    0x8CD37CF3, 0xFBD44C65, 0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
    0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC,
    0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3,
    0xB966D409, 0xCE61E49F, 0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
    0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,

    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF,
    0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
    0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1, 0xF00F9344, 0x8708A3D2,
    0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9,
    0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
    0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B, 0xD80D2BDA, 0xAF0A1B4C,
    0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703,
    0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
    0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,

    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
    0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
    0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
    0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
    0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
    0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
};
enum class KCSStatus : uint8_t
{
    Disable = 0x00,
    Enable = 0x01,
};

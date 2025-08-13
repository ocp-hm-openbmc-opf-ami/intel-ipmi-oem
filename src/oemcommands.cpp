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

#include "ipmid/net_utility.hpp"
#include "types.hpp"
#include "xyz/openbmc_project/Common/error.hpp"
#include "xyz/openbmc_project/Led/Physical/server.hpp"

#include <fcntl.h>
#include <grp.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <netinet/ether.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <security/pam_appl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <systemd/sd-journal.h>
#include <unistd.h>

#include <appcommands.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/process/child.hpp>
#include <boost/process/io.hpp>
#include <com/intel/Control/OCOTShutdownPolicy/server.hpp>
#include <commandutils.hpp>
#include <gpiod.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <oemcommands.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/types.hpp>
#include <stdplus/net/addr/subnet.hpp>
#include <stdplus/raw.hpp>
#include <xyz/openbmc_project/Chassis/Control/NMISource/server.hpp>
#include <xyz/openbmc_project/Control/Boot/Mode/server.hpp>
#include <xyz/openbmc_project/Control/Boot/Source/server.hpp>
#include <xyz/openbmc_project/Control/PowerSupplyRedundancy/server.hpp>
#include <xyz/openbmc_project/Control/Security/RestrictionMode/server.hpp>
#include <xyz/openbmc_project/Control/Security/SpecialMode/server.hpp>
#include <xyz/openbmc_project/Network/FirewallConfiguration/server.hpp>
#include <xyz/openbmc_project/Software/Activation/server.hpp>
#include <xyz/openbmc_project/Software/Version/server.hpp>
/*TODO: enable once phosphor-dbus-interface patch updated
#include <xyz/openbmc_project/USB/status/server.hpp>
*/

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <set>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

namespace ipmi
{
// IPMI OEM USB Linux Gadget info
static constexpr uint16_t USB_VENDOR_ID = 0x0525;
static constexpr uint16_t USB_PRODUCT_ID = 0xA4A2;
static constexpr uint8_t USB_SERIAL_NUM = 0x00;

// Network object in dbus
static constexpr auto networkServiceName = "xyz.openbmc_project.Network";
static constexpr auto networkConfigObj = "/xyz/openbmc_project/network/config";
static constexpr auto networkConfigIntf =
    "xyz.openbmc_project.Network.SystemConfiguration";

// IPMI channel info
// static constexpr uint8_t maxIpmiChannels = 16;
static constexpr const char* channelConfigDefaultFilename =
    "/usr/share/ipmi-providers/channel_config.json";

// STRING DEFINES: Should sync with key's in JSON
static constexpr const char* nameString = "name";
static constexpr const char* isValidString = "is_valid";
static constexpr const char* channelInfoString = "channel_info";
static constexpr const char* mediumTypeString = "medium_type";
static constexpr const char* protocolTypeString = "protocol_type";
static constexpr const char* sessionSupportedString = "session_supported";
static constexpr const char* isIpmiString = "is_ipmi";
static constexpr const char* redfishHostInterfaceChannel = "usb0";

// User Manager object in dbus
static constexpr const char* userMgrObjBasePath = "/xyz/openbmc_project/user";
static constexpr const char* userMgrInterface =
    "xyz.openbmc_project.User.Manager";
static constexpr const char* usersInterface =
    "xyz.openbmc_project.User.Attributes";
static constexpr const char* usersDeleteIface =
    "xyz.openbmc_project.Object.Delete";
static constexpr const char* createUserMethod = "CreateUser";
static constexpr const char* deleteUserMethod = "Delete";

// BIOSConfig Manager object in dbus
static constexpr const char* biosConfigMgrPath =
    "/xyz/openbmc_project/bios_config/manager";
static constexpr const char* biosConfigMgrIface =
    "xyz.openbmc_project.BIOSConfig.Manager";

using GetSubTreePathsType = std::vector<std::string>;

using namespace phosphor::logging;

// Cert Paths
std::string defaultCertPath = "/etc/ssl/certs/https/server.pem";

static constexpr const char* persistentDataFilePath =
    "/home/root/bmcweb_persistent_data.json";

constexpr size_t ipmbMaxDataSize = 256;
static void registerOEMFunctions() __attribute__((constructor));

static constexpr size_t maxFRUStringLength = 0x3F;

// BIOS PostCode return error code
static constexpr Cc ipmiCCBIOSPostCodeError = 0x89;

// HI Certificate FingerPrint error code
static constexpr Cc ipmiCCBootStrappingDisabled = 0x80;
static constexpr Cc ipmiCCCertificateNumberInvalid = 0xCB;

static constexpr Cc ipmiCCFileSelectorOrOffsetAndLengthOutOfRange = 0xC9;
static constexpr Cc ipmiCCNoCertGenerated = 0x83;

static constexpr auto ethernetIntf =
    "xyz.openbmc_project.Network.EthernetInterface";
static constexpr auto networkIPIntf = "xyz.openbmc_project.Network.IP";
static constexpr auto networkService = "xyz.openbmc_project.Network";
static constexpr auto networkRoot = "/xyz/openbmc_project/network";

static constexpr const char* oemNmiSourceIntf =
    "xyz.openbmc_project.Chassis.Control.NMISource";
static constexpr const char* oemNmiSourceObjPath =
    "/xyz/openbmc_project/Chassis/Control/NMISource";
static constexpr const char* oemNmiBmcSourceObjPathProp = "BMCSource";
static constexpr const char* oemNmiEnabledObjPathProp = "Enabled";

static constexpr const char* dimmOffsetFile = "/var/lib/ipmi/ipmi_dimms.json";
static constexpr const char* multiNodeObjPath =
    "/xyz/openbmc_project/MultiNode/Status";
static constexpr const char* multiNodeIntf =
    "xyz.openbmc_project.Chassis.MultiNode";
const static constexpr char* systemDService = "org.freedesktop.systemd1";
const static constexpr char* systemDObjPath = "/org/freedesktop/systemd1";
const static constexpr char* systemDMgrIntf =
    "org.freedesktop.systemd1.Manager";
const std::string ipmiKcsService = "phosphor-ipmi-kcs@ipmi_kcs3.service";
constexpr auto systemDInterfaceUnit = "org.freedesktop.DBus.Properties";
constexpr auto activeState = "active";
constexpr auto activatingState = "activating";

const static constexpr char* settingsService = "xyz.openbmc_project.Settings";
const static constexpr char* settingsObjPath =
    "/xyz/openbmc_project/logging/settings";
const static constexpr char* settingsUSBIntf = "xyz.openbmc_project.USB";

const static constexpr char* snmpService = "xyz.openbmc_project.Snmp";
const static constexpr char* snmpObjPath = "/xyz/openbmc_project/Snmp";
const static constexpr char* snmpUtilsIntf =
    "xyz.openbmc_project.Snmp.SnmpUtils";
// Task
static constexpr auto taskIntf = "xyz.openbmc_project.Common.Task";
static constexpr auto systemRoot = "/xyz/openbmc_project/";
static constexpr uint8_t INVALID_ID = 0x00;
static constexpr auto cancelTask =
    "xyz.openbmc_project.Common.Task.OperationStatus.Cancelled";
static constexpr auto newTask =
    "xyz.openbmc_project.Common.Task.OperationStatus.New";

// BIOS PostCode object in dbus
static constexpr const char* postCodesService =
    "xyz.openbmc_project.State.Boot.PostCode0";
static constexpr const char* postCodesObjPath =
    "/xyz/openbmc_project/State/Boot/PostCode0";
static constexpr const char* postCodesIntf =
    "xyz.openbmc_project.State.Boot.PostCode";
const static constexpr char* postCodesProp = "CurrentBootCycleCount";

static constexpr const char* chassisStateService =
    "xyz.openbmc_project.State.Chassis";
static constexpr const char* chassisStatePath =
    "/xyz/openbmc_project/state/chassis0";
static constexpr const char* chassisStateIntf =
    "xyz.openbmc_project.State.Chassis";

static constexpr uint8_t maxlentimezone = 64;

constexpr bool debug = false;

enum class NmiSource : uint8_t
{
    none = 0,
    frontPanelButton = 1,
    watchdog = 2,
    chassisCmd = 3,
    memoryError = 4,
    pciBusError = 5,
    pch = 6,
    chipset = 7,
};

enum class SpecialUserIndex : uint8_t
{
    rootUser = 0,
    atScaleDebugUser = 1
};

static constexpr const char* restricionModeService =
    "xyz.openbmc_project.RestrictionMode.Manager";
static constexpr const char* restricionModeBasePath =
    "/xyz/openbmc_project/control/security/restriction_mode";
static constexpr const char* restricionModeIntf =
    "xyz.openbmc_project.Control.Security.RestrictionMode";
static constexpr const char* restricionModeProperty = "RestrictionMode";

static constexpr const char* specialModeService =
    "xyz.openbmc_project.SpecialMode";
static constexpr const char* specialModeBasePath =
    "/xyz/openbmc_project/security/special_mode";
static constexpr const char* specialModeIntf =
    "xyz.openbmc_project.Security.SpecialMode";
static constexpr const char* specialModeProperty = "SpecialMode";

static constexpr const char* dBusPropertyIntf =
    "org.freedesktop.DBus.Properties";
static constexpr const char* dBusPropertyGetMethod = "Get";
static constexpr const char* dBusPropertySetMethod = "Set";

// return code: 0 successful
int8_t getChassisSerialNumber(sdbusplus::bus_t& bus, std::string& serial)
{
    std::string objpath = "/xyz/openbmc_project/FruDevice";
    std::string intf = "xyz.openbmc_project.FruDeviceManager";
    std::string service = getService(bus, intf, objpath);
    ObjectValueTree valueTree = getManagedObjects(bus, service, "/");
    if (valueTree.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "No object implements interface",
            phosphor::logging::entry("INTF=%s", intf.c_str()));
        return -1;
    }

    for (const auto& item : valueTree)
    {
        auto interface = item.second.find("xyz.openbmc_project.FruDevice");
        if (interface == item.second.end())
        {
            continue;
        }

        auto property = interface->second.find("CHASSIS_SERIAL_NUMBER");
        if (property == interface->second.end())
        {
            continue;
        }

        try
        {
            Value variant = property->second;
            std::string& result = std::get<std::string>(variant);
            if (result.size() > maxFRUStringLength)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "FRU serial number exceed maximum length");
                return -1;
            }
            serial = result;
            return 0;
        }
        catch (const std::bad_variant_access& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return -1;
        }
    }
    return -1;
}

namespace mailbox
{
static uint8_t bus = 4;
static std::string i2cBus = "/dev/i2c-" + std::to_string(bus);
static uint8_t targetAddr = 56;
static constexpr auto systemRoot = "/xyz/openbmc_project/inventory/system";
static constexpr auto sessionIntf = "xyz.openbmc_project.Configuration.PFR";
const std::string match = "Baseboard/PFR";
static bool i2cConfigLoaded = false;
// Command register for UFM provisioning/access commands; read/write allowed
// from CPU/BMC.
static const constexpr uint8_t provisioningCommand = 0x0b;
// Trigger register for the command set in the previous offset.
static const constexpr uint8_t triggerCommand = 0x0c;
// Set 0x0c to 0x05 to execute command specified at “UFM/Provisioning Command”
// register
static const constexpr uint8_t flushRead = 0x05;
// FIFO read registers
std::set<uint8_t> readFifoReg = {0x08, 0x0C, 0x0D, 0x13};

// UFM Read FIFO
static const constexpr uint8_t readFifo = 0x0e;

enum registerType : uint8_t
{
    singleByteRegister = 0,
    fifoReadRegister,

};

void loadPfrConfig(ipmi::Context::ptr& ctx, bool& i2cConfigLoaded)
{
    ipmi::ObjectTree objectTree;

    boost::system::error_code ec = ipmi::getAllDbusObjects(
        ctx, systemRoot, sessionIntf, match, objectTree);

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to fetch PFR object from dbus",
            phosphor::logging::entry("INTERFACE=%s", sessionIntf),
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));

        return;
    }

    for (auto& softObject : objectTree)
    {
        const std::string& objPath = softObject.first;
        const std::string& serviceName = softObject.second.begin()->first;
        // PFR object found.. check for PFR support
        ipmi::PropertyMap result;

        ec = ipmi::getAllDbusProperties(ctx, serviceName, objPath, sessionIntf,
                                        result);

        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to fetch pfr properties",
                phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
            return;
        }

        const uint64_t* i2cBusNum = nullptr;
        const uint64_t* address = nullptr;

        for (const auto& [propName, propVariant] : result)
        {
            if (propName == "Address")
            {
                address = std::get_if<uint64_t>(&propVariant);
            }
            else if (propName == "Bus")
            {
                i2cBusNum = std::get_if<uint64_t>(&propVariant);
            }
        }

        if ((address == nullptr) || (i2cBusNum == nullptr))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unable to read the pfr properties");
            return;
        }

        bus = static_cast<int>(*i2cBusNum);
        i2cBus = "/dev/i2c-" + std::to_string(bus);
        targetAddr = static_cast<int>(*address);

        i2cConfigLoaded = true;
    }
}

void writefifo(const uint8_t cmdReg, const uint8_t val)
{
    // Based on the spec, writing cmdReg to address val on this device, will
    // trigger the write FIFO operation.
    std::vector<uint8_t> writeData = {cmdReg, val};
    std::vector<uint8_t> readBuf(0);
    ipmi::Cc retI2C =
        ipmi::i2cWriteRead(i2cBus, targetAddr, writeData, readBuf);
    if (retI2C)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "i2cWriteRead returns non-zero");
    }
}

} // namespace mailbox

ipmi::RspType<std::string> ipmiOEMGetBmcVersionString()
{
    static std::string version{};
    if (version.empty())
    {
        std::regex expr{"^VERSION_ID=(.*)$"};
        static constexpr auto osReleasePath{"/etc/os-release"};
        std::ifstream ifs(osReleasePath);
        if (!ifs.is_open())
        {
            version = "os-release not present";
        }
        std::string line{};
        while (std::getline(ifs, line))
        {
            std::smatch sm;
            if (regex_match(line, sm, expr))
            {
                if (sm.size() == 2)
                {
                    std::string v = sm[1].str();
                    // remove the quotes
                    v.erase(std::remove(v.begin(), v.end(), '\"'), v.end());
                    version = v;
                    break;
                }
            }
        }
        ifs.close();
        if (version.empty())
        {
            version = "VERSION_ID not present";
        }
    }
    return ipmi::responseSuccess(version);
}

// Returns the Chassis Identifier (serial #)
ipmi_ret_t ipmiOEMGetChassisIdentifier(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                                       ipmi_response_t response,
                                       ipmi_data_len_t dataLen, ipmi_context_t)
{
    std::string serial;
    if (*dataLen != 0) // invalid request if there are extra parameters
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    if (getChassisSerialNumber(*dbus, serial) == 0)
    {
        *dataLen = serial.size(); // length will never exceed response length
                                  // as it is checked in getChassisSerialNumber
        char* resp = static_cast<char*>(response);
        serial.copy(resp, *dataLen);
        return IPMI_CC_OK;
    }
    *dataLen = 0;
    return IPMI_CC_RESPONSE_ERROR;
}

ipmi_ret_t ipmiOEMSetSystemGUID(ipmi_netfn_t, ipmi_cmd_t,
                                ipmi_request_t request, ipmi_response_t,
                                ipmi_data_len_t dataLen, ipmi_context_t)
{
    static constexpr size_t safeBufferLength = 50;
    char buf[safeBufferLength] = {0};
    GUIDData* Data = reinterpret_cast<GUIDData*>(request);

    if (*dataLen != sizeof(GUIDData)) // 16bytes
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *dataLen = 0;

    snprintf(
        buf, safeBufferLength,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        Data->timeLow4, Data->timeLow3, Data->timeLow2, Data->timeLow1,
        Data->timeMid2, Data->timeMid1, Data->timeHigh2, Data->timeHigh1,
        Data->clock2, Data->clock1, Data->node6, Data->node5, Data->node4,
        Data->node3, Data->node2, Data->node1);
    // UUID is in RFC4122 format. Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
    std::string guid = buf;

    std::string objpath = "/xyz/openbmc_project/control/host0/systemGUID";
    std::string intf = "xyz.openbmc_project.Common.UUID";
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service = getService(*dbus, intf, objpath);
    setDbusProperty(*dbus, service, objpath, intf, "UUID", guid);
    return IPMI_CC_OK;
}

ipmi::RspType<> ipmiOEMDisableBMCSystemReset(bool disableResetOnSMI,
                                             uint7_t reserved1)
{
    if (reserved1)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();

    try
    {
        auto service =
            ipmi::getService(*busp, bmcResetDisablesIntf, bmcResetDisablesPath);
        ipmi::setDbusProperty(*busp, service, bmcResetDisablesPath,
                              bmcResetDisablesIntf, "ResetOnSMI",
                              !disableResetOnSMI);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set BMC reset disables",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<bool,   // disableResetOnSMI
              uint7_t // reserved
              >
    ipmiOEMGetBMCResetDisables()
{
    bool disableResetOnSMI = true;

    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    try
    {
        auto service =
            ipmi::getService(*busp, bmcResetDisablesIntf, bmcResetDisablesPath);
        Value variant =
            ipmi::getDbusProperty(*busp, service, bmcResetDisablesPath,
                                  bmcResetDisablesIntf, "ResetOnSMI");
        disableResetOnSMI = !std::get<bool>(variant);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get BMC reset disables",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(disableResetOnSMI, 0);
}

ipmi_ret_t ipmiOEMSetBIOSID(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request,
                            ipmi_response_t response, ipmi_data_len_t dataLen,
                            ipmi_context_t)
{
    DeviceInfo* data = reinterpret_cast<DeviceInfo*>(request);

    if ((*dataLen < 2ul) || (*dataLen != (1ul + data->biosIDLength)))
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    std::string idString((char*)data->biosId, data->biosIDLength);
    for (auto idChar : idString)
    {
        if (!std::isprint(static_cast<unsigned char>(idChar)))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "BIOS ID contains non printable character");
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
    }

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service = getService(*dbus, biosVersionIntf, biosActiveObjPath);
    setDbusProperty(*dbus, service, biosActiveObjPath, biosVersionIntf,
                    biosVersionProp, idString);
    uint8_t* bytesWritten = static_cast<uint8_t*>(response);
    *bytesWritten =
        data->biosIDLength; // how many bytes are written into storage
    *dataLen = 1;
    return IPMI_CC_OK;
}

bool getActiveHSCSoftwareVersionInfo(std::string& hscVersion, size_t hscNumber)
{
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        std::string hsbpObjPath =
            "/xyz/openbmc_project/software/HSBP_" + std::to_string(hscNumber);
        auto service = getService(*dbus, biosVersionIntf, hsbpObjPath);
        Value hscVersionValue =
            getDbusProperty(*dbus, "xyz.openbmc_project.HsbpManager",
                            hsbpObjPath, biosVersionIntf, "Version");
        hscVersion = std::get<std::string>(hscVersionValue);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Failed to retrieve HSBP version information",
            phosphor::logging::entry("HSBP Number=%d", hscNumber));
        return false;
    }
    return true;
}

bool getHscVerInfo(ipmi::Context::ptr&, uint8_t& hsc0Major, uint8_t& hsc0Minor,
                   uint8_t& hsc1Major, uint8_t& hsc1Minor, uint8_t& hsc2Major,
                   uint8_t& hsc2Minor)
{
    std::string hscVersion;
    std::array<uint8_t, 6> hscVersions{0};

    for (size_t hscNumber = 1; hscNumber <= 3; hscNumber++)
    {
        if (!getActiveHSCSoftwareVersionInfo(hscVersion, hscNumber))
        {
            continue;
        }
        std::regex pattern1("(\\d+?).(\\d+?).(\\d+?)");
        constexpr size_t matchedPhosphor = 4;
        std::smatch results;
        // hscVersion = BOOT_VER.FPGA_VER.SECURITY_REVISION (Example: 00.02.01)
        if (std::regex_match(hscVersion, results, pattern1))
        {
            // Major version is FPGA_VER and Minor version is SECURITY_REV
            if (results.size() == matchedPhosphor)
            {
                int index = (hscNumber - 1) * 2;
                hscVersions[index] =
                    static_cast<uint8_t>(std::stoi(results[2]));
                hscVersions[index + 1] =
                    static_cast<uint8_t>(std::stoi(results[3]));
            }
        }
    }
    hsc0Major = hscVersions[0];
    hsc0Minor = hscVersions[1];
    hsc1Major = hscVersions[2];
    hsc1Minor = hscVersions[3];
    hsc2Major = hscVersions[4];
    hsc2Minor = hscVersions[5];
    return true;
}

bool getSwVerInfo(ipmi::Context::ptr& ctx, uint8_t& bmcMajor, uint8_t& bmcMinor,
                  uint8_t& meMajor, uint8_t& meMinor)
{
    // step 1 : get BMC Major and Minor numbers from its DBUS property
    std::string bmcVersion;
    if (getActiveSoftwareVersionInfo(ctx, versionPurposeBMC, bmcVersion))
    {
        return false;
    }

    std::optional<MetaRevision> rev = convertIntelVersion(bmcVersion);
    if (rev.has_value())
    {
        MetaRevision revision = rev.value();
        bmcMajor = revision.major;

        revision.minor = (revision.minor > 99 ? 99 : revision.minor);
        bmcMinor = revision.minor % 10 + (revision.minor / 10) * 16;
    }

    // step 2 : get ME Major and Minor numbers from its DBUS property
    std::string meVersion;
    if (getActiveSoftwareVersionInfo(ctx, versionPurposeME, meVersion))
    {
        return false;
    }
    std::regex pattern1("(\\d+?).(\\d+?).(\\d+?).(\\d+?).(\\d+?)");
    constexpr size_t matchedPhosphor = 6;
    std::smatch results;
    if (std::regex_match(meVersion, results, pattern1))
    {
        if (results.size() == matchedPhosphor)
        {
            meMajor = static_cast<uint8_t>(std::stoi(results[1]));
            meMinor = static_cast<uint8_t>(
                std::stoi(results[2]) << 4 | std::stoi(results[3]));
        }
    }
    return true;
}

ipmi::RspType<
    std::variant<std::string,
                 std::tuple<uint8_t, std::array<uint8_t, 2>,
                            std::array<uint8_t, 2>, std::array<uint8_t, 2>,
                            std::array<uint8_t, 2>, std::array<uint8_t, 2>>,
                 std::tuple<uint8_t, std::array<uint8_t, 2>>>>
    ipmiOEMGetDeviceInfo(ipmi::Context::ptr& ctx, uint8_t entityType,
                         std::optional<uint8_t> countToRead,
                         std::optional<uint8_t> offset)
{
    if (entityType > static_cast<uint8_t>(OEMDevEntityType::sdrVer))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // handle OEM command items
    switch (OEMDevEntityType(entityType))
    {
        case OEMDevEntityType::biosId:
        {
            // Byte 2&3, Only used with selecting BIOS
            if (!countToRead || !offset)
            {
                return ipmi::responseReqDataLenInvalid();
            }

            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            std::string service =
                getService(*dbus, biosVersionIntf, biosActiveObjPath);
            try
            {
                Value variant =
                    getDbusProperty(*dbus, service, biosActiveObjPath,
                                    biosVersionIntf, biosVersionProp);
                std::string& idString = std::get<std::string>(variant);
                if (*offset >= idString.size())
                {
                    return ipmi::responseParmOutOfRange();
                }
                size_t length = 0;
                if (*countToRead > (idString.size() - *offset))
                {
                    length = idString.size() - *offset;
                }
                else
                {
                    length = *countToRead;
                }

                std::string readBuf = {0};
                readBuf.resize(length);
                std::copy_n(idString.begin() + *offset, length,
                            (readBuf.begin()));
                return ipmi::responseSuccess(readBuf);
            }
            catch (const std::bad_variant_access& e)
            {
                return ipmi::responseUnspecifiedError();
            }
        }
        break;

        case OEMDevEntityType::devVer:
        {
            // Byte 2&3, Only used with selecting BIOS
            if (countToRead || offset)
            {
                return ipmi::responseReqDataLenInvalid();
            }

            constexpr const size_t verLen = 2;
            constexpr const size_t verTotalLen = 10;
            std::array<uint8_t, verLen> bmcBuf = {0xff, 0xff};
            std::array<uint8_t, verLen> hsc0Buf = {0xff, 0xff};
            std::array<uint8_t, verLen> hsc1Buf = {0xff, 0xff};
            std::array<uint8_t, verLen> meBuf = {0xff, 0xff};
            std::array<uint8_t, verLen> hsc2Buf = {0xff, 0xff};
            // data0/1: BMC version number; data6/7: ME version number
            if (!getSwVerInfo(ctx, bmcBuf[0], bmcBuf[1], meBuf[0], meBuf[1]))
            {
                return ipmi::responseUnspecifiedError();
            }
            if (!getHscVerInfo(ctx, hsc0Buf[0], hsc0Buf[1], hsc1Buf[0],
                               hsc1Buf[1], hsc2Buf[0], hsc2Buf[1]))
            {
                return ipmi::responseUnspecifiedError();
            }
            return ipmi::responseSuccess(
                std::tuple<
                    uint8_t, std::array<uint8_t, verLen>,
                    std::array<uint8_t, verLen>, std::array<uint8_t, verLen>,
                    std::array<uint8_t, verLen>, std::array<uint8_t, verLen>>{
                    verTotalLen, bmcBuf, hsc0Buf, hsc1Buf, meBuf, hsc2Buf});
        }
        break;

        case OEMDevEntityType::sdrVer:
        {
            // Byte 2&3, Only used with selecting BIOS
            if (countToRead || offset)
            {
                return ipmi::responseReqDataLenInvalid();
            }

            constexpr const size_t sdrLen = 2;
            std::array<uint8_t, sdrLen> readBuf = {0x01, 0x0};
            return ipmi::responseSuccess(
                std::tuple<uint8_t, std::array<uint8_t, sdrLen>>{sdrLen,
                                                                 readBuf});
        }
        break;

        default:
            return ipmi::responseInvalidFieldRequest();
    }
}

ipmi_ret_t ipmiOEMGetAICFRU(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                            ipmi_response_t response, ipmi_data_len_t dataLen,
                            ipmi_context_t)
{
    if (*dataLen != 0)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *dataLen = 1;
    uint8_t* res = reinterpret_cast<uint8_t*>(response);
    // temporary fix. We don't support AIC FRU now. Just tell BIOS that no
    // AIC is available so that BIOS will not timeout repeatly which leads to
    // slow booting.
    *res = 0; // Byte1=Count of SlotPosition/FruID records.
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiOEMGetPowerRestoreDelay(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                                       ipmi_response_t response,
                                       ipmi_data_len_t dataLen, ipmi_context_t)
{
    GetPowerRestoreDelayRes* resp =
        reinterpret_cast<GetPowerRestoreDelayRes*>(response);

    if (*dataLen != 0)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service =
        getService(*dbus, powerRestoreDelayIntf, powerRestoreDelayObjPath);
    Value variant =
        getDbusProperty(*dbus, service, powerRestoreDelayObjPath,
                        powerRestoreDelayIntf, powerRestoreDelayProp);

    uint64_t val = std::get<uint64_t>(variant);
    val /= 1000000UL;
    uint16_t delay = val;
    resp->byteLSB = delay;
    resp->byteMSB = delay >> 8;

    *dataLen = sizeof(GetPowerRestoreDelayRes);

    return IPMI_CC_OK;
}

static uint8_t bcdToDec(uint8_t val)
{
    return ((val / 16 * 10) + (val % 16));
}

// Allows an update utility or system BIOS to send the status of an embedded
// firmware update attempt to the BMC. After received, BMC will create a logging
// record.
ipmi::RspType<> ipmiOEMSendEmbeddedFwUpdStatus(
    uint8_t status, uint8_t target, uint8_t majorRevision,
    uint8_t minorRevision, uint32_t auxInfo)
{
    std::string firmware;
    int instance = (target & targetInstanceMask) >> targetInstanceShift;
    target = (target & selEvtTargetMask) >> selEvtTargetShift;

    /* make sure the status is 0, 1, or 2 as per the spec */
    if (status > 2)
    {
        return ipmi::response(ipmi::ccInvalidFieldRequest);
    }
    /* make sure the target is 0, 1, 2, or 4 as per the spec */
    if (target > 4 || target == 3)
    {
        return ipmi::response(ipmi::ccInvalidFieldRequest);
    }
    /*orignal OEM command is to record OEM SEL.
    But openbmc does not support OEM SEL, so we redirect it to redfish event
    logging. */
    std::string buildInfo;
    std::string action;
    switch (FWUpdateTarget(target))
    {
        case FWUpdateTarget::targetBMC:
            firmware = "BMC";
            buildInfo = "major: " + std::to_string(majorRevision) + " minor: " +
                        std::to_string(bcdToDec(minorRevision)) + // BCD encoded
                        " BuildID: " + std::to_string(auxInfo);
            buildInfo += std::to_string(auxInfo);
            break;
        case FWUpdateTarget::targetBIOS:
            firmware = "BIOS";
            buildInfo =
                "major: " +
                std::to_string(bcdToDec(majorRevision)) + // BCD encoded
                " minor: " +
                std::to_string(bcdToDec(minorRevision)) + // BCD encoded
                " ReleaseNumber: " +                      // ASCII encoded
                std::to_string(static_cast<uint8_t>(auxInfo >> 0) - '0') +
                std::to_string(static_cast<uint8_t>(auxInfo >> 8) - '0') +
                std::to_string(static_cast<uint8_t>(auxInfo >> 16) - '0') +
                std::to_string(static_cast<uint8_t>(auxInfo >> 24) - '0');
            break;
        case FWUpdateTarget::targetME:
            firmware = "ME";
            buildInfo =
                "major: " + std::to_string(majorRevision) + " minor1: " +
                std::to_string(bcdToDec(minorRevision)) + // BCD encoded
                " minor2: " +
                std::to_string(bcdToDec(static_cast<uint8_t>(auxInfo >> 0))) +
                " build1: " +
                std::to_string(bcdToDec(static_cast<uint8_t>(auxInfo >> 8))) +
                " build2: " +
                std::to_string(bcdToDec(static_cast<uint8_t>(auxInfo >> 16)));
            break;
        case FWUpdateTarget::targetOEMEWS:
            firmware = "EWS";
            buildInfo = "major: " + std::to_string(majorRevision) + " minor: " +
                        std::to_string(bcdToDec(minorRevision)) + // BCD encoded
                        " BuildID: " + std::to_string(auxInfo);
            break;
    }

    static const std::string openBMCMessageRegistryVersion("0.1");
    std::string redfishMsgID = "OpenBMC." + openBMCMessageRegistryVersion;

    switch (status)
    {
        case 0x0:
            action = "update started";
            redfishMsgID += ".FirmwareUpdateStarted";
            break;
        case 0x1:
            action = "update completed successfully";
            redfishMsgID += ".FirmwareUpdateCompleted";
            break;
        case 0x2:
            action = "update failure";
            redfishMsgID += ".FirmwareUpdateFailed";
            break;
        default:
            action = "unknown";
            break;
    }

    std::string firmwareInstanceStr =
        firmware + " instance: " + std::to_string(instance);
    std::string message("[firmware update] " + firmwareInstanceStr +
                        " status: <" + action + "> " + buildInfo);

    sd_journal_send("MESSAGE=%s", message.c_str(), "PRIORITY=%i", LOG_INFO,
                    "REDFISH_MESSAGE_ID=%s", redfishMsgID.c_str(),
                    "REDFISH_MESSAGE_ARGS=%s,%s", firmwareInstanceStr.c_str(),
                    buildInfo.c_str(), NULL);
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t, std::vector<uint8_t>> ipmiOEMSlotIpmb(
    ipmi::Context::ptr& ctx, uint6_t reserved1, uint2_t slotNumber,
    uint3_t baseBoardSlotNum, [[maybe_unused]] uint3_t riserSlotNum,
    uint2_t reserved2, uint8_t targetAddr, uint8_t netFn, uint8_t cmd,
    std::optional<std::vector<uint8_t>> writeData)
{
    if (reserved1 || reserved2)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    boost::system::error_code ec;
    using ipmbResponse = std::tuple<int, uint8_t, uint8_t, uint8_t, uint8_t,
                                    std::vector<uint8_t>>;
    ipmbResponse res = ctx->bus->yield_method_call<ipmbResponse>(
        ctx->yield, ec, "xyz.openbmc_project.Ipmi.Channel.Ipmb",
        "/xyz/openbmc_project/Ipmi/Channel/Ipmb", "org.openbmc.Ipmb",
        "SlotIpmbRequest", static_cast<uint8_t>(slotNumber),
        static_cast<uint8_t>(baseBoardSlotNum), targetAddr, netFn, cmd,
        *writeData);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to call dbus method SlotIpmbRequest");
        return ipmi::responseUnspecifiedError();
    }

    std::vector<uint8_t> dataReceived(0);
    int status = -1;
    uint8_t resNetFn = 0, resLun = 0, resCmd = 0, cc = 0;

    std::tie(status, resNetFn, resLun, resCmd, cc, dataReceived) = res;

    if (status)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get response from SlotIpmbRequest");
        return ipmi::responseResponseError();
    }
    return ipmi::responseSuccess(cc, dataReceived);
}

ipmi_ret_t ipmiOEMSetPowerRestoreDelay(ipmi_netfn_t, ipmi_cmd_t,
                                       ipmi_request_t request, ipmi_response_t,
                                       ipmi_data_len_t dataLen, ipmi_context_t)
{
    SetPowerRestoreDelayReq* data =
        reinterpret_cast<SetPowerRestoreDelayReq*>(request);
    uint16_t delay = 0;

    if (*dataLen != sizeof(SetPowerRestoreDelayReq))
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    delay = data->byteMSB;
    delay = (delay << 8) | data->byteLSB;
    uint64_t val = delay * 1000000;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service =
        getService(*dbus, powerRestoreDelayIntf, powerRestoreDelayObjPath);
    setDbusProperty(*dbus, service, powerRestoreDelayObjPath,
                    powerRestoreDelayIntf, powerRestoreDelayProp, val);
    *dataLen = 0;

    return IPMI_CC_OK;
}

static bool cpuPresent(const std::string& cpuName)
{
    static constexpr const char* cpuPresencePathPrefix =
        "/xyz/openbmc_project/inventory/system/chassis/motherboard/";
    static constexpr const char* cpuPresenceIntf =
        "xyz.openbmc_project.Inventory.Item";
    std::string cpuPresencePath = cpuPresencePathPrefix + cpuName;
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    try
    {
        auto service =
            ipmi::getService(*busp, cpuPresenceIntf, cpuPresencePath);

        ipmi::Value result = ipmi::getDbusProperty(
            *busp, service, cpuPresencePath, cpuPresenceIntf, "Present");
        return std::get<bool>(result);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Cannot find processor presence",
            phosphor::logging::entry("NAME=%s", cpuName.c_str()));
        return false;
    }
}

ipmi::RspType<bool,    // IERR Reset Enabled
              bool,    // ERR2 Reset Enabled
              bool,    // MCERR Reset Enabled
              uint5_t, // reserved
              uint8_t, // reserved, returns 0x3F
              uint6_t, // CPU1 IERR Count
              uint2_t, // CPU1 Status
              uint6_t, // CPU2 IERR Count
              uint2_t, // CPU2 Status
              uint6_t, // CPU3 IERR Count
              uint2_t, // CPU3 Status
              uint6_t, // CPU4 IERR Count
              uint2_t, // CPU4 Status
              uint8_t  // Crashdump Count
              >
    ipmiOEMGetProcessorErrConfig()
{
    bool resetOnIERR = false;
    bool resetOnERR2 = false;
    bool resetOnMCERR = false;
    uint6_t cpu1IERRCount = 0;
    uint6_t cpu2IERRCount = 0;
    uint6_t cpu3IERRCount = 0;
    uint6_t cpu4IERRCount = 0;
    uint8_t crashdumpCount = 0;
    uint2_t cpu1Status = cpuPresent("CPU_1")
                             ? types::enum_cast<uint8_t>(CPUStatus::enabled)
                             : types::enum_cast<uint8_t>(CPUStatus::notPresent);
    uint2_t cpu2Status = cpuPresent("CPU_2")
                             ? types::enum_cast<uint8_t>(CPUStatus::enabled)
                             : types::enum_cast<uint8_t>(CPUStatus::notPresent);
    uint2_t cpu3Status = cpuPresent("CPU_3")
                             ? types::enum_cast<uint8_t>(CPUStatus::enabled)
                             : types::enum_cast<uint8_t>(CPUStatus::notPresent);
    uint2_t cpu4Status = cpuPresent("CPU_4")
                             ? types::enum_cast<uint8_t>(CPUStatus::enabled)
                             : types::enum_cast<uint8_t>(CPUStatus::notPresent);

    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    try
    {
        auto service = ipmi::getService(*busp, processorErrConfigIntf,
                                        processorErrConfigObjPath);

        ipmi::PropertyMap result = ipmi::getAllDbusProperties(
            *busp, service, processorErrConfigObjPath, processorErrConfigIntf);
        resetOnIERR = std::get<bool>(result.at("ResetOnIERR"));
        resetOnERR2 = std::get<bool>(result.at("ResetOnERR2"));
        resetOnMCERR = std::get<bool>(result.at("ResetOnMCERR"));
        cpu1IERRCount = std::get<uint8_t>(result.at("ErrorCountCPU1"));
        cpu2IERRCount = std::get<uint8_t>(result.at("ErrorCountCPU2"));
        cpu3IERRCount = std::get<uint8_t>(result.at("ErrorCountCPU3"));
        cpu4IERRCount = std::get<uint8_t>(result.at("ErrorCountCPU4"));
        crashdumpCount = std::get<uint8_t>(result.at("CrashdumpCount"));
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to fetch processor error config",
            phosphor::logging::entry("ERROR=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(
        resetOnIERR, resetOnERR2, resetOnMCERR, 0, 0x3F, cpu1IERRCount,
        cpu1Status, cpu2IERRCount, cpu2Status, cpu3IERRCount, cpu3Status,
        cpu4IERRCount, cpu4Status, crashdumpCount);
}

ipmi::RspType<> ipmiOEMSetProcessorErrConfig(
    bool resetOnIERR, bool resetOnERR2, bool resetOnMCERR, uint5_t reserved1,
    uint8_t reserved2, std::optional<bool> clearCPUErrorCount,
    std::optional<bool> clearCrashdumpCount, std::optional<uint6_t> reserved3)
{
    if (reserved1 || reserved2)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();

    try
    {
        if (reserved3.value_or(0))
        {
            return ipmi::responseInvalidFieldRequest();
        }
        auto service = ipmi::getService(*busp, processorErrConfigIntf,
                                        processorErrConfigObjPath);
        ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                              processorErrConfigIntf, "ResetOnIERR",
                              resetOnIERR);
        ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                              processorErrConfigIntf, "ResetOnERR2",
                              resetOnERR2);
        ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                              processorErrConfigIntf, "ResetOnMCERR",
                              resetOnMCERR);
        if (clearCPUErrorCount.value_or(false))
        {
            ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                                  processorErrConfigIntf, "ErrorCountCPU1",
                                  static_cast<uint8_t>(0));
            ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                                  processorErrConfigIntf, "ErrorCountCPU2",
                                  static_cast<uint8_t>(0));
            ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                                  processorErrConfigIntf, "ErrorCountCPU3",
                                  static_cast<uint8_t>(0));
            ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                                  processorErrConfigIntf, "ErrorCountCPU4",
                                  static_cast<uint8_t>(0));
        }
        if (clearCrashdumpCount.value_or(false))
        {
            ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                                  processorErrConfigIntf, "CrashdumpCount",
                                  static_cast<uint8_t>(0));
        }
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set processor error config",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

ipmi_ret_t ipmiOEMGetShutdownPolicy(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                                    ipmi_response_t response,
                                    ipmi_data_len_t dataLen, ipmi_context_t)
{
    GetOEMShutdownPolicyRes* resp =
        reinterpret_cast<GetOEMShutdownPolicyRes*>(response);

    if (*dataLen != 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "oem_get_shutdown_policy: invalid input len!");
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *dataLen = 0;

    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service =
            getService(*dbus, oemShutdownPolicyIntf, oemShutdownPolicyObjPath);
        Value variant = getDbusProperty(
            *dbus, service, oemShutdownPolicyObjPath, oemShutdownPolicyIntf,
            oemShutdownPolicyObjPathProp);

        if (sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::
                convertPolicyFromString(std::get<std::string>(variant)) ==
            sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::Policy::
                NoShutdownOnOCOT)
        {
            resp->policy = 0;
        }
        else if (sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::
                     convertPolicyFromString(std::get<std::string>(variant)) ==
                 sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::
                     Policy::ShutdownOnOCOT)
        {
            resp->policy = 1;
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "oem_set_shutdown_policy: invalid property!",
                phosphor::logging::entry(
                    "PROP=%s", std::get<std::string>(variant).c_str()));
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        // TODO needs to check if it is multi-node products,
        // policy is only supported on node 3/4
        resp->policySupport = shutdownPolicySupported;
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.description());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    *dataLen = sizeof(GetOEMShutdownPolicyRes);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiOEMSetShutdownPolicy(ipmi_netfn_t, ipmi_cmd_t,
                                    ipmi_request_t request, ipmi_response_t,
                                    ipmi_data_len_t dataLen, ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);
    sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::Policy policy =
        sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::Policy::
            NoShutdownOnOCOT;

    // TODO needs to check if it is multi-node products,
    // policy is only supported on node 3/4
    if (*dataLen != 1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "oem_set_shutdown_policy: invalid input len!");
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *dataLen = 0;
    if ((*req != noShutdownOnOCOT) && (*req != shutdownOnOCOT))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "oem_set_shutdown_policy: invalid input!");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (*req == noShutdownOnOCOT)
    {
        policy = sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::
            Policy::NoShutdownOnOCOT;
    }
    else
    {
        policy = sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::
            Policy::ShutdownOnOCOT;
    }

    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service =
            getService(*dbus, oemShutdownPolicyIntf, oemShutdownPolicyObjPath);
        setDbusProperty(
            *dbus, service, oemShutdownPolicyObjPath, oemShutdownPolicyIntf,
            oemShutdownPolicyObjPathProp,
            sdbusplus::com::intel::Control::server::convertForMessage(policy));
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.description());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    return IPMI_CC_OK;
}

/** @brief implementation for check the DHCP or not in IPv4
 *  @param[in] Channel - Channel number
 *  @returns true or false.
 */
static bool isDHCPEnabled(uint8_t Channel)
{
    try
    {
        auto ethdevice = getChannelName(Channel);
        if (ethdevice.empty())
        {
            return false;
        }
        auto ethIP = ethdevice + "/ipv4";
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        auto ethernetObj =
            getDbusObject(*dbus, networkIPIntf, networkRoot, ethIP);
        auto value = getDbusProperty(*dbus, networkService, ethernetObj.first,
                                     networkIPIntf, "Origin");
        if (std::get<std::string>(value) ==
            "xyz.openbmc_project.Network.IP.AddressOrigin.DHCP")
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.description());
        return true;
    }
}

/** @brief implementes for check the DHCP or not in IPv6
 *  @param[in] Channel - Channel number
 *  @returns true or false.
 */
static bool isDHCPIPv6Enabled(uint8_t Channel)
{
    try
    {
        auto ethdevice = getChannelName(Channel);
        if (ethdevice.empty())
        {
            return false;
        }
        auto ethIP = ethdevice + "/ipv6";
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        auto objectInfo =
            getDbusObject(*dbus, networkIPIntf, networkRoot, ethIP);
        auto properties = getAllDbusProperties(*dbus, objectInfo.second,
                                               objectInfo.first, networkIPIntf);
        if (std::get<std::string>(properties["Origin"]) ==
            "xyz.openbmc_project.Network.IP.AddressOrigin.DHCP")
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.description());
        return true;
    }
}

/** @brief implementes the creating of default new user
 *  @param[in] userName - new username in 16 bytes.
 *  @param[in] userPassword - new password in 20 bytes
 *  @returns ipmi completion code.
 */
ipmi::RspType<> ipmiOEMSetUser2Activation(
    std::array<uint8_t, ipmi::ipmiMaxUserName>& userName,
    const SecureBuffer& userPassword)
{
    if (userPassword.size() != ipmi::maxIpmi20PasswordSize)
    {
        return ipmi::responseReqDataLenInvalid();
    }
    bool userState = false;
    // Check for System Interface not exist and LAN should be static
    for (uint8_t channel = 0; channel < maxIpmiChannels; channel++)
    {
        ChannelInfo chInfo{};
        try
        {
            getChannelInfo(channel, chInfo);
        }
        catch (const sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetUser2Activation: Failed to get Channel Info",
                phosphor::logging::entry("MSG: %s", e.description()));
            return ipmi::response(ipmi::ccUnspecifiedError);
        }
        if (chInfo.mediumType ==
            static_cast<uint8_t>(EChannelMediumType::systemInterface))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetUser2Activation: system interface  exist .");
            return ipmi::response(ipmi::ccCommandNotAvailable);
        }
        else
        {
            if (chInfo.mediumType ==
                static_cast<uint8_t>(EChannelMediumType::lan8032))
            {
                if (isDHCPIPv6Enabled(channel) || isDHCPEnabled(channel))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "ipmiOEMSetUser2Activation: DHCP enabled .");
                    return ipmi::response(ipmi::ccCommandNotAvailable);
                }
            }
        }
    }
    uint8_t maxChUsers = 0, enabledUsers = 0, fixedUsers = 0;
    if (ipmi::ccSuccess ==
        ipmiUserGetAllCounts(maxChUsers, enabledUsers, fixedUsers))
    {
        if (enabledUsers > 1)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetUser2Activation: more than one user is enabled.");
            return ipmi::response(ipmi::ccCommandNotAvailable);
        }
        // Check the user 2 is enabled or not
        ipmiUserCheckEnabled(ipmiDefaultUserId, userState);
        if (userState == true)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetUser2Activation: user 2 already enabled .");
            return ipmi::response(ipmi::ccCommandNotAvailable);
        }
    }
    else
    {
        return ipmi::response(ipmi::ccUnspecifiedError);
    }

#if BYTE_ORDER == LITTLE_ENDIAN
    PrivAccess privAccess = {PRIVILEGE_ADMIN, true, true, true, 0};
#endif
#if BYTE_ORDER == BIG_ENDIAN
    PrivAccess privAccess = {0, true, true, true, PRIVILEGE_ADMIN};
#endif

    // ipmiUserSetUserName correctly handles char*, possibly non-null
    // terminated strings using ipmiMaxUserName size
    size_t nameLen = strnlen(reinterpret_cast<const char*>(userName.data()),
                             sizeof(userName));
    const std::string userNameRaw(
        reinterpret_cast<const char*>(userName.data()), nameLen);

    if (ipmi::ccSuccess == ipmiUserSetUserName(ipmiDefaultUserId, userNameRaw))
    {
        if (ipmi::ccSuccess ==
            ipmiUserSetUserPassword(
                ipmiDefaultUserId,
                reinterpret_cast<const char*>(userPassword.data())))
        {
            if (ipmi::ccSuccess ==
                ipmiUserSetPrivilegeAccess(
                    ipmiDefaultUserId,
                    static_cast<uint8_t>(ipmi::EChannelID::chanLan1),
                    privAccess, true))
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    "ipmiOEMSetUser2Activation: user created successfully ");

                return ipmi::responseSuccess();
            }
        }
        // we need to delete  the default user id which added in this command as
        // password / priv setting is failed.
        ipmiUserSetUserName(ipmiDefaultUserId, static_cast<std::string>(""));
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetUser2Activation: password / priv setting is failed.");
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetUser2Activation: Setting username failed.");
    }

    return ipmi::response(ipmi::ccCommandNotAvailable);
}

/** @brief implementes executing the linux command
 *  @param[in] linux command
 *  @returns status
 */

static uint8_t executeCmd(const char* path)
{
    boost::process::child execProg(path);
    execProg.wait();

    int retCode = execProg.exit_code();
    if (retCode)
    {
        return ipmi::ccUnspecifiedError;
    }
    return ipmi::ccSuccess;
}

/** @brief implementes ASD Security event logging
 *  @param[in] Event message string
 *  @param[in] Event Severity
 *  @returns status
 */

static void atScaleDebugEventlog(std::string msg, int severity)
{
    std::string eventStr = "OpenBMC.0.1." + msg;
    sd_journal_send("MESSAGE=Security Event: %s", eventStr.c_str(),
                    "PRIORITY=%i", severity, "REDFISH_MESSAGE_ID=%s",
                    eventStr.c_str(), NULL);
}

/** @brief implementes setting password for special user
 *  @param[in] specialUserIndex
 *  @param[in] userPassword - new password in 20 bytes
 *  @returns ipmi completion code.
 */
ipmi::RspType<> ipmiOEMSetSpecialUserPassword(ipmi::Context::ptr& ctx,
                                              uint8_t specialUserIndex,
                                              std::vector<uint8_t> userPassword)
{
    ChannelInfo chInfo;
    ipmi_ret_t status = ipmi::ccSuccess;

    try
    {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetSpecialUserPassword: Failed to get Channel Info",
            phosphor::logging::entry("MSG: %s", e.description()));
        return ipmi::responseUnspecifiedError();
    }
    if (chInfo.mediumType !=
        static_cast<uint8_t>(EChannelMediumType::systemInterface))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetSpecialUserPassword: Error - supported only in KCS "
            "interface");
        return ipmi::responseCommandNotAvailable();
    }

    // 0 for root user  and 1 for AtScaleDebug is allowed
    if (specialUserIndex >
        static_cast<uint8_t>(SpecialUserIndex::atScaleDebugUser))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetSpecialUserPassword: Invalid user account");
        return ipmi::responseParmOutOfRange();
    }
    if (userPassword.size() != 0)
    {
        constexpr uint8_t minPasswordSizeRequired = 6;
        SecureString passwd;
        if (userPassword.size() < minPasswordSizeRequired ||
            userPassword.size() > ipmi::maxIpmi20PasswordSize)
        {
            OPENSSL_cleanse(userPassword.data(), userPassword.size());
            return ipmi::responseReqDataLenInvalid();
        }
        passwd.assign(reinterpret_cast<const char*>(userPassword.data()),
                      userPassword.size());
        // Clear sensitive data
        OPENSSL_cleanse(userPassword.data(), userPassword.size());
        if (specialUserIndex ==
            static_cast<uint8_t>(SpecialUserIndex::atScaleDebugUser))
        {
            status = ipmiSetSpecialUserPassword("asdbg", passwd);

            atScaleDebugEventlog("AtScaleDebugSpecialUserEnabled", LOG_CRIT);
        }
        else
        {
            status = ipmiSetSpecialUserPassword("root", passwd);
        }
        return ipmi::response(status);
    }
    else
    {
        if (specialUserIndex ==
            static_cast<uint8_t>(SpecialUserIndex::rootUser))
        {
            status = executeCmd("passwd -d root");
        }
        else
        {
            status = executeCmd("passwd -d asdbg");

            if (status == 0)
            {
                atScaleDebugEventlog("AtScaleDebugSpecialUserDisabled",
                                     LOG_INFO);
            }
        }
        return ipmi::response(status);
    }
}

namespace ledAction
{
using namespace sdbusplus::xyz::openbmc_project::Led::server;
std::map<Physical::Action, uint8_t> actionDbusToIpmi = {
    {Physical::Action::Off, 0},
    {Physical::Action::On, 2},
    {Physical::Action::Blink, 1}};

std::map<uint8_t, std::string> offsetObjPath = {
    {2, statusAmberObjPath}, {4, statusGreenObjPath}, {6, identifyLEDObjPath}};

} // namespace ledAction

int8_t getLEDState(sdbusplus::bus_t& bus, const std::string& intf,
                   const std::string& objPath, uint8_t& state)
{
    try
    {
        std::string service = getService(bus, intf, objPath);
        Value stateValue =
            getDbusProperty(bus, service, objPath, intf, "State");
        std::string strState = std::get<std::string>(stateValue);
        state = ledAction::actionDbusToIpmi.at(
            sdbusplus::xyz::openbmc_project::Led::server::Physical::
                convertActionFromString(strState));
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return -1;
    }
    return 0;
}

ipmi::RspType<uint8_t> ipmiOEMGetLEDStatus()
{
    uint8_t ledstate = 0;
    phosphor::logging::log<phosphor::logging::level::DEBUG>("GET led status");
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    for (auto it = ledAction::offsetObjPath.begin();
         it != ledAction::offsetObjPath.end(); ++it)
    {
        uint8_t state = 0;
        if (getLEDState(*dbus, ledIntf, it->second, state) == -1)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "oem_get_led_status: fail to get ID LED status!");
            return ipmi::responseUnspecifiedError();
        }
        ledstate |= state << it->first;
    }
    return ipmi::responseSuccess(ledstate);
}

ipmi_ret_t ipmiOEMCfgHostSerialPortSpeed(
    ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request, ipmi_response_t response,
    ipmi_data_len_t dataLen, ipmi_context_t)
{
    CfgHostSerialReq* req = reinterpret_cast<CfgHostSerialReq*>(request);
    uint8_t* resp = reinterpret_cast<uint8_t*>(response);

    if (*dataLen == 0)
    {
        if constexpr (debug)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "CfgHostSerial: invalid input len!",
                phosphor::logging::entry("LEN=%d", *dataLen));
        }
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    switch (req->command)
    {
        case getHostSerialCfgCmd:
        {
            if (*dataLen != 1)
            {
                if constexpr (debug)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "CfgHostSerial: invalid input len!");
                }
                *dataLen = 0;
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            *dataLen = 0;

            boost::process::ipstream is;
            std::vector<std::string> data;
            std::string line;
            boost::process::child c1(fwGetEnvCmd, "-n", fwHostSerailCfgEnvName,
                                     boost::process::std_out > is);

            while (c1.running() && std::getline(is, line) && !line.empty())
            {
                data.push_back(line);
            }

            c1.wait();
            if (c1.exit_code())
            {
                if constexpr (debug)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "CfgHostSerial:: error on execute",
                        phosphor::logging::entry("EXECUTE=%s", fwSetEnvCmd));
                }
                // Using the default value
                *resp = 0;
            }
            else
            {
                if (data.size() != 1)
                {
                    if constexpr (debug)
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "CfgHostSerial:: error on read env");
                    }
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                try
                {
                    unsigned long tmp = std::stoul(data[0]);
                    if (tmp > std::numeric_limits<uint8_t>::max())
                    {
                        throw std::out_of_range("Out of range");
                    }
                    *resp = static_cast<uint8_t>(tmp);
                }
                catch (const std::invalid_argument& e)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "invalid config ",
                        phosphor::logging::entry("ERR=%s", e.what()));
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                catch (const std::out_of_range& e)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "out_of_range config ",
                        phosphor::logging::entry("ERR=%s", e.what()));
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
            }

            *dataLen = 1;
            break;
        }
        case setHostSerialCfgCmd:
        {
            if (*dataLen != sizeof(CfgHostSerialReq))
            {
                if constexpr (debug)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "CfgHostSerial: invalid input len!");
                }
                *dataLen = 0;
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            *dataLen = 0;

            if (req->parameter > HostSerialCfgParamMax)
            {
                if constexpr (debug)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "CfgHostSerial: invalid input!");
                }
                return IPMI_CC_INVALID_FIELD_REQUEST;
            }

            boost::process::child c1(fwSetEnvCmd, fwHostSerailCfgEnvName,
                                     std::to_string(req->parameter));

            c1.wait();
            if (c1.exit_code())
            {
                if constexpr (debug)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "CfgHostSerial:: error on execute",
                        phosphor::logging::entry("EXECUTE=%s", fwGetEnvCmd));
                }
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            break;
        }
        default:
            if constexpr (debug)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "CfgHostSerial: invalid input!");
            }
            *dataLen = 0;
            return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    return IPMI_CC_OK;
}

constexpr const char* thermalModeInterface =
    "xyz.openbmc_project.Control.ThermalMode";
constexpr const char* thermalModePath =
    "/xyz/openbmc_project/control/thermal_mode";

bool getFanProfileInterface(
    sdbusplus::bus_t& bus,
    boost::container::flat_map<std::string, ipmi::DbusVariant>& resp)
{
    auto call = bus.new_method_call(settingsBusName, thermalModePath, PROP_INTF,
                                    "GetAll");
    call.append(thermalModeInterface);
    try
    {
        auto data = bus.call(call);
        data.read(resp);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getFanProfileInterface: can't get thermal mode!",
            phosphor::logging::entry("ERR=%s", e.what()));
        return false;
    }
    return true;
}

/**@brief implements the OEM set fan config.
 * @param selectedFanProfile - fan profile to enable
 * @param reserved1
 * @param performanceMode - Performance/Acoustic mode
 * @param reserved2
 * @param setPerformanceMode - set Performance/Acoustic mode
 * @param setFanProfile - set fan profile
 *
 * @return IPMI completion code.
 **/
ipmi::RspType<> ipmiOEMSetFanConfig(
    [[maybe_unused]] uint8_t selectedFanProfile, uint2_t reserved1,
    bool performanceMode, uint3_t reserved2, bool setPerformanceMode,
    [[maybe_unused]] bool setFanProfile, std::optional<uint8_t> dimmGroupId,
    [[maybe_unused]] std::optional<uint32_t> dimmPresenceBitmap)
{
    if (reserved1 || reserved2)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (dimmGroupId)
    {
        if (*dimmGroupId >= maxCPUNum)
        {
            return ipmi::responseInvalidFieldRequest();
        }
        if (!cpuPresent("cpu" + std::to_string(*dimmGroupId)))
        {
            return ipmi::responseInvalidFieldRequest();
        }
    }

    // todo: tell bios to only send first 2 bytes
    boost::container::flat_map<std::string, ipmi::DbusVariant> profileData;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    if (!getFanProfileInterface(*dbus, profileData))
    {
        return ipmi::responseUnspecifiedError();
    }

    std::vector<std::string>* supported =
        std::get_if<std::vector<std::string>>(&profileData["Supported"]);
    if (supported == nullptr)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    std::string mode;
    if (setPerformanceMode)
    {
        if (performanceMode)
        {
            if (std::find(supported->begin(), supported->end(),
                          "Performance") != supported->end())
            {
                mode = "Performance";
            }
        }
        else
        {
            if (std::find(supported->begin(), supported->end(), "Acoustic") !=
                supported->end())
            {
                mode = "Acoustic";
            }
        }
        if (mode.empty())
        {
            return ipmi::responseInvalidFieldRequest();
        }

        try
        {
            setDbusProperty(*dbus, settingsBusName, thermalModePath,
                            thermalModeInterface, "Current", mode);
        }
        catch (const sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetFanConfig: can't set thermal mode!",
                phosphor::logging::entry("EXCEPTION=%s", e.what()));
            return ipmi::responseResponseError();
        }
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t, // profile support map
              uint8_t, // fan control profile enable
              uint8_t, // flags
              uint32_t // dimm presence bit map
              >
    ipmiOEMGetFanConfig(uint8_t dimmGroupId)
{
    if (dimmGroupId >= maxCPUNum)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    bool cpuStatus = cpuPresent("cpu" + std::to_string(dimmGroupId));

    if (!cpuStatus)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    boost::container::flat_map<std::string, ipmi::DbusVariant> profileData;

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    if (!getFanProfileInterface(*dbus, profileData))
    {
        return ipmi::responseResponseError();
    }

    std::string* current = std::get_if<std::string>(&profileData["Current"]);

    if (current == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMGetFanConfig: can't get current mode!");
        return ipmi::responseResponseError();
    }
    bool performance = (*current == "Performance");

    uint8_t flags = 0;
    if (performance)
    {
        flags |= 1 << 2;
    }

    constexpr uint8_t fanControlDefaultProfile = 0x80;
    constexpr uint8_t fanControlProfileState = 0x00;
    constexpr uint32_t dimmPresenceBitmap = 0x00;

    return ipmi::responseSuccess(fanControlDefaultProfile,
                                 fanControlProfileState, flags,
                                 dimmPresenceBitmap);
}
constexpr const char* cfmLimitSettingPath =
    "/xyz/openbmc_project/control/cfm_limit";
constexpr const char* cfmLimitIface = "xyz.openbmc_project.Control.CFMLimit";
constexpr const size_t legacyExitAirSensorNumber = 0x2e;
constexpr const size_t legacyPCHSensorNumber = 0x22;
constexpr const char* exitAirPathName = "Exit_Air";
constexpr const char* pchPathName = "SSB_Temp";
constexpr const char* pidConfigurationIface =
    "xyz.openbmc_project.Configuration.Pid";

static std::string getConfigPath(const std::string& name)
{
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    auto method =
        dbus->new_method_call("xyz.openbmc_project.ObjectMapper",
                              "/xyz/openbmc_project/object_mapper",
                              "xyz.openbmc_project.ObjectMapper", "GetSubTree");

    method.append("/", 0, std::array<const char*, 1>{pidConfigurationIface});
    std::string path;
    GetSubTreeType resp;
    try
    {
        auto reply = dbus->call(method);
        reply.read(resp);
    }
    catch (const sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMGetFscParameter: mapper error");
    };
    auto config =
        std::find_if(resp.begin(), resp.end(), [&name](const auto& pair) {
            return pair.first.find(name) != std::string::npos;
        });
    if (config != resp.end())
    {
        path = std::move(config->first);
    }
    return path;
}

// flat map to make alphabetical
static boost::container::flat_map<std::string, PropertyMap> getPidConfigs()
{
    boost::container::flat_map<std::string, PropertyMap> ret;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    auto method =
        dbus->new_method_call("xyz.openbmc_project.ObjectMapper",
                              "/xyz/openbmc_project/object_mapper",
                              "xyz.openbmc_project.ObjectMapper", "GetSubTree");

    method.append("/", 0, std::array<const char*, 1>{pidConfigurationIface});
    GetSubTreeType resp;

    try
    {
        auto reply = dbus->call(method);
        reply.read(resp);
    }
    catch (const sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getFanConfigPaths: mapper error");
    };
    for (const auto& [path, objects] : resp)
    {
        if (objects.empty())
        {
            continue; // should be impossible
        }

        try
        {
            ret.emplace(path,
                        getAllDbusProperties(*dbus, objects[0].first, path,
                                             pidConfigurationIface));
        }
        catch (const sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "getPidConfigs: can't get DbusProperties!",
                phosphor::logging::entry("ERR=%s", e.what()));
        }
    }
    return ret;
}

ipmi::RspType<uint8_t> ipmiOEMGetFanSpeedOffset(void)
{
    boost::container::flat_map<std::string, PropertyMap> data = getPidConfigs();
    if (data.empty())
    {
        return ipmi::responseResponseError();
    }
    uint8_t minOffset = std::numeric_limits<uint8_t>::max();
    for (const auto& [_, pid] : data)
    {
        auto findClass = pid.find("Class");
        if (findClass == pid.end())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMGetFscParameter: found illegal pid "
                "configurations");
            return ipmi::responseResponseError();
        }
        std::string type = std::get<std::string>(findClass->second);
        if (type == "fan")
        {
            auto findOutLimit = pid.find("OutLimitMin");
            if (findOutLimit == pid.end())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMGetFscParameter: found illegal pid "
                    "configurations");
                return ipmi::responseResponseError();
            }
            // get the min out of all the offsets
            minOffset = std::min(
                minOffset,
                static_cast<uint8_t>(std::get<double>(findOutLimit->second)));
        }
    }
    if (minOffset == std::numeric_limits<uint8_t>::max())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMGetFscParameter: found no fan configurations!");
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(minOffset);
}

ipmi::RspType<> ipmiOEMSetFanSpeedOffset(uint8_t offset)
{
    constexpr uint8_t maxFanSpeedOffset = 100;
    if (offset > maxFanSpeedOffset)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetFanSpeedOffset: fan offset greater than limit");
        return ipmi::responseInvalidFieldRequest();
    }
    boost::container::flat_map<std::string, PropertyMap> data = getPidConfigs();
    if (data.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetFanSpeedOffset: found no pid configurations!");
        return ipmi::responseResponseError();
    }

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    bool found = false;
    for (const auto& [path, pid] : data)
    {
        auto findClass = pid.find("Class");
        if (findClass == pid.end())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetFanSpeedOffset: found illegal pid "
                "configurations");
            return ipmi::responseResponseError();
        }
        std::string type = std::get<std::string>(findClass->second);
        if (type == "fan")
        {
            auto findOutLimit = pid.find("OutLimitMin");
            if (findOutLimit == pid.end())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMSetFanSpeedOffset: found illegal pid "
                    "configurations");
                return ipmi::responseResponseError();
            }
            ipmi::setDbusProperty(*dbus, "xyz.openbmc_project.EntityManager",
                                  path, pidConfigurationIface, "OutLimitMin",
                                  static_cast<double>(offset));
            found = true;
        }
    }
    if (!found)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetFanSpeedOffset: set no fan offsets");
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<> ipmiOEMSetFscParameter(uint8_t command, uint8_t param1,
                                       uint8_t param2)
{
    constexpr const size_t disableLimiting = 0x0;

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    if (command == static_cast<uint8_t>(setFscParamFlags::tcontrol))
    {
        std::string pathName;
        if (param1 == legacyExitAirSensorNumber)
        {
            pathName = exitAirPathName;
        }
        else if (param1 == legacyPCHSensorNumber)
        {
            pathName = pchPathName;
        }
        else
        {
            return ipmi::responseParmOutOfRange();
        }
        std::string path = getConfigPath(pathName);
        ipmi::setDbusProperty(*dbus, "xyz.openbmc_project.EntityManager", path,
                              pidConfigurationIface, "SetPoint",
                              static_cast<double>(param2));
        return ipmi::responseSuccess();
    }
    else if (command == static_cast<uint8_t>(setFscParamFlags::cfm))
    {
        uint16_t cfm = param1 | (static_cast<uint16_t>(param2) << 8);

        // must be greater than 50 based on eps
        if (cfm < 50 && cfm != disableLimiting)
        {
            return ipmi::responseParmOutOfRange();
        }

        try
        {
            ipmi::setDbusProperty(*dbus, settingsBusName, cfmLimitSettingPath,
                                  cfmLimitIface, "Limit",
                                  static_cast<double>(cfm));
        }
        catch (const sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetFscParameter: can't set cfm setting!",
                phosphor::logging::entry("ERR=%s", e.what()));
            return ipmi::responseResponseError();
        }
        return ipmi::responseSuccess();
    }
    else if (command == static_cast<uint8_t>(setFscParamFlags::maxPwm))
    {
        uint8_t requestedDomainMask = param1;
        boost::container::flat_map data = getPidConfigs();
        if (data.empty())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetFscParameter: found no pid configurations!");
            return ipmi::responseResponseError();
        }
        size_t count = 0;
        for (const auto& [path, pid] : data)
        {
            auto findClass = pid.find("Class");
            if (findClass == pid.end())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMSetFscParameter: found illegal pid "
                    "configurations");
                return ipmi::responseResponseError();
            }
            std::string type = std::get<std::string>(findClass->second);
            if (type == "fan")
            {
                if (requestedDomainMask & (1 << count))
                {
                    ipmi::setDbusProperty(
                        *dbus, "xyz.openbmc_project.EntityManager", path,
                        pidConfigurationIface, "OutLimitMax",
                        static_cast<double>(param2));
                }
                count++;
            }
        }
        return ipmi::responseSuccess();
    }
    else
    {
        // todo other command parts possibly
        // tcontrol is handled in peci now
        // fan speed offset not implemented yet
        // domain pwm limit not implemented
        return ipmi::responseParmOutOfRange();
    }
}

ipmi::RspType<
    std::variant<uint8_t, std::array<uint8_t, 2>, std::array<uint16_t, 2>>>
    ipmiOEMGetFscParameter(uint8_t command, std::optional<uint8_t> param)
{
    constexpr uint8_t legacyDefaultSetpoint = -128;

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    if (command == static_cast<uint8_t>(setFscParamFlags::tcontrol))
    {
        if (!param)
        {
            return ipmi::responseReqDataLenInvalid();
        }

        std::string pathName;

        if (*param == legacyExitAirSensorNumber)
        {
            pathName = exitAirPathName;
        }
        else if (*param == legacyPCHSensorNumber)
        {
            pathName = pchPathName;
        }
        else
        {
            return ipmi::responseParmOutOfRange();
        }

        uint8_t setpoint = legacyDefaultSetpoint;
        std::string path = getConfigPath(pathName);
        if (path.size())
        {
            Value val = ipmi::getDbusProperty(
                *dbus, "xyz.openbmc_project.EntityManager", path,
                pidConfigurationIface, "SetPoint");
            setpoint = std::floor(std::get<double>(val) + 0.5);
        }

        // old implementation used to return the "default" and current, we
        // don't make the default readily available so just make both the
        // same

        return ipmi::responseSuccess(
            std::array<uint8_t, 2>{setpoint, setpoint});
    }
    else if (command == static_cast<uint8_t>(setFscParamFlags::maxPwm))
    {
        constexpr const size_t maxDomainCount = 8;

        if (!param)
        {
            return ipmi::responseReqDataLenInvalid();
        }
        uint8_t requestedDomain = *param;
        if (requestedDomain >= maxDomainCount)
        {
            return ipmi::responseInvalidFieldRequest();
        }

        boost::container::flat_map data = getPidConfigs();
        if (data.empty())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMGetFscParameter: found no pid configurations!");
            return ipmi::responseResponseError();
        }
        size_t count = 0;
        for (const auto& [_, pid] : data)
        {
            auto findClass = pid.find("Class");
            if (findClass == pid.end())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMGetFscParameter: found illegal pid "
                    "configurations");
                return ipmi::responseResponseError();
            }
            std::string type = std::get<std::string>(findClass->second);
            if (type == "fan")
            {
                if (requestedDomain == count)
                {
                    auto findOutLimit = pid.find("OutLimitMax");
                    if (findOutLimit == pid.end())
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "ipmiOEMGetFscParameter: found illegal pid "
                            "configurations");
                        return ipmi::responseResponseError();
                    }

                    return ipmi::responseSuccess(
                        static_cast<uint8_t>(std::floor(
                            std::get<double>(findOutLimit->second) + 0.5)));
                }
                else
                {
                    count++;
                }
            }
        }

        return ipmi::responseInvalidFieldRequest();
    }
    else if (command == static_cast<uint8_t>(setFscParamFlags::cfm))
    {
        /*
        DataLen should be 1, but host is sending us an extra bit. As the
        previous behavior didn't seem to prevent this, ignore the check for
        now.

        if (param)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMGetFscParameter: invalid input len!");
            return IPMI_CC_REQ_DATA_LEN_INVALID;
        }
        */
        Value cfmLimit;
        Value cfmMaximum;
        try
        {
            cfmLimit = ipmi::getDbusProperty(*dbus, settingsBusName,
                                             cfmLimitSettingPath, cfmLimitIface,
                                             "Limit");
            cfmMaximum = ipmi::getDbusProperty(
                *dbus, "xyz.openbmc_project.ExitAirTempSensor",
                "/xyz/openbmc_project/control/MaxCFM", cfmLimitIface, "Limit");
        }
        catch (const sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMGetFscParameter: can't get cfm setting!",
                phosphor::logging::entry("ERR=%s", e.what()));
            return ipmi::responseResponseError();
        }

        double cfmMax = std::get<double>(cfmMaximum);
        double cfmLim = std::get<double>(cfmLimit);

        cfmLim = std::floor(cfmLim + 0.5);
        cfmMax = std::floor(cfmMax + 0.5);
        uint16_t cfmLimResp = static_cast<uint16_t>(cfmLim);
        uint16_t cfmMaxResp = static_cast<uint16_t>(cfmMax);

        return ipmi::responseSuccess(
            std::array<uint16_t, 2>{cfmLimResp, cfmMaxResp});
    }

    else
    {
        // todo other command parts possibly
        // domain pwm limit not implemented
        return ipmi::responseParmOutOfRange();
    }
}

using crConfigVariant = ipmi::DbusVariant;

int setCRConfig(ipmi::Context::ptr& ctx, const std::string& property,
                const crConfigVariant& value,
                [[maybe_unused]] std::chrono::microseconds timeout =
                    ipmi::IPMI_DBUS_TIMEOUT)
{
    boost::system::error_code ec;
    ctx->bus->yield_method_call<void>(
        ctx->yield, ec, "xyz.openbmc_project.PSURedundancy",
        "/xyz/openbmc_project/control/power_supply_redundancy",
        "org.freedesktop.DBus.Properties", "Set",
        "xyz.openbmc_project.Control.PowerSupplyRedundancy", property, value);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set dbus property to cold redundancy");
        return -1;
    }

    return 0;
}

int getCRConfig(
    ipmi::Context::ptr& ctx, const std::string& property,
    crConfigVariant& value,
    const std::string& service = "xyz.openbmc_project.PSURedundancy",
    [[maybe_unused]] std::chrono::microseconds timeout =
        ipmi::IPMI_DBUS_TIMEOUT)
{
    boost::system::error_code ec;
    value = ctx->bus->yield_method_call<crConfigVariant>(
        ctx->yield, ec, service,
        "/xyz/openbmc_project/control/power_supply_redundancy",
        "org.freedesktop.DBus.Properties", "Get",
        "xyz.openbmc_project.Control.PowerSupplyRedundancy", property);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get dbus property to cold redundancy");
        return -1;
    }
    return 0;
}

uint8_t getPSUCount(void)
{
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    ipmi::Value num;
    try
    {
        num = ipmi::getDbusProperty(
            *dbus, "xyz.openbmc_project.PSURedundancy",
            "/xyz/openbmc_project/control/power_supply_redundancy",
            "xyz.openbmc_project.Control.PowerSupplyRedundancy", "PSUNumber");
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get PSUNumber property from dbus interface");
        return 0;
    }
    uint8_t* pNum = std::get_if<uint8_t>(&num);
    if (!pNum)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error to get PSU Number");
        return 0;
    }
    return *pNum;
}

bool validateCRAlgo(std::vector<uint8_t>& conf, uint8_t num)
{
    if (conf.size() < num)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid PSU Ranking");
        return false;
    }
    std::set<uint8_t> confSet;
    for (uint8_t i = 0; i < num; i++)
    {
        if (conf[i] > num)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "PSU Ranking is larger than current PSU number");
            return false;
        }
        confSet.emplace(conf[i]);
    }

    if (confSet.size() != num)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "duplicate PSU Ranking");
        return false;
    }
    return true;
}

enum class crParameter
{
    crStatus = 0,
    crFeature = 1,
    rotationFeature = 2,
    rotationAlgo = 3,
    rotationPeriod = 4,
    numOfPSU = 5,
    rotationRankOrderEffective = 6
};

constexpr ipmi::Cc ccParameterNotSupported = 0x80;
static const constexpr uint32_t oneDay = 0x15180;
static const constexpr uint32_t oneMonth = 0xf53700;
static const constexpr uint8_t userSpecific = 0x01;
static const constexpr uint8_t crSetCompleted = 0;
ipmi::RspType<uint8_t> ipmiOEMSetCRConfig(
    ipmi::Context::ptr& ctx, uint8_t parameter, ipmi::message::Payload& payload)
{
    switch (static_cast<crParameter>(parameter))
    {
        case crParameter::rotationFeature:
        {
            uint8_t param1;
            if (payload.unpack(param1) || !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            // Rotation Enable can only be true or false
            if (param1 > 1)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            if (setCRConfig(ctx, "RotationEnabled", static_cast<bool>(param1)))
            {
                return ipmi::responseResponseError();
            }
            break;
        }
        case crParameter::rotationAlgo:
        {
            // Rotation Algorithm can only be 0-BMC Specific or 1-User Specific
            std::string algoName;
            uint8_t param1;
            if (payload.unpack(param1))
            {
                return ipmi::responseReqDataLenInvalid();
            }
            switch (param1)
            {
                case 0:
                    algoName = "xyz.openbmc_project.Control."
                               "PowerSupplyRedundancy.Algo.bmcSpecific";
                    break;
                case 1:
                    algoName = "xyz.openbmc_project.Control."
                               "PowerSupplyRedundancy.Algo.userSpecific";
                    break;
                default:
                    return ipmi::responseInvalidFieldRequest();
            }
            if (setCRConfig(ctx, "RotationAlgorithm", algoName))
            {
                return ipmi::responseResponseError();
            }

            uint8_t numberOfPSU = getPSUCount();
            if (!numberOfPSU)
            {
                return ipmi::responseResponseError();
            }
            std::vector<uint8_t> rankOrder;

            if (param1 == userSpecific)
            {
                if (payload.unpack(rankOrder) || !payload.fullyUnpacked())
                {
                    ipmi::responseReqDataLenInvalid();
                }
                if (rankOrder.size() != numberOfPSU)
                {
                    return ipmi::responseReqDataLenInvalid();
                }

                if (!validateCRAlgo(rankOrder, numberOfPSU))
                {
                    return ipmi::responseInvalidFieldRequest();
                }
            }
            else
            {
                if (rankOrder.size() > 0)
                {
                    return ipmi::responseReqDataLenInvalid();
                }
                for (uint8_t i = 1; i <= numberOfPSU; i++)
                {
                    rankOrder.emplace_back(i);
                }
            }
            if (setCRConfig(ctx, "RotationRankOrder", rankOrder))
            {
                return ipmi::responseResponseError();
            }
            break;
        }
        case crParameter::rotationPeriod:
        {
            // Minimum Rotation period is  One day (86400 seconds) and Max
            // Rotation Period is 6 month (0xf53700 seconds)
            uint32_t period;
            if (payload.unpack(period) || !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            if ((period < oneDay) || (period > oneMonth))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            if (setCRConfig(ctx, "PeriodOfRotation", period))
            {
                return ipmi::responseResponseError();
            }
            break;
        }
        default:
        {
            return ipmi::response(ccParameterNotSupported);
        }
    }

    return ipmi::responseSuccess(crSetCompleted);
}

ipmi::RspType<uint8_t, std::variant<uint8_t, uint32_t, std::vector<uint8_t>>>
    ipmiOEMGetCRConfig(ipmi::Context::ptr& ctx, uint8_t parameter)
{
    crConfigVariant value;
    switch (static_cast<crParameter>(parameter))
    {
        case crParameter::crStatus:
        {
            if (getCRConfig(ctx, "ColdRedundancyStatus", value))
            {
                return ipmi::responseResponseError();
            }
            std::string* pStatus = std::get_if<std::string>(&value);
            if (!pStatus)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error to get ColdRedundancyStatus property");
                return ipmi::responseResponseError();
            }
            namespace server = sdbusplus::xyz::openbmc_project::Control::server;
            auto status =
                server::PowerSupplyRedundancy::convertStatusFromString(
                    *pStatus);
            switch (status)
            {
                case server::PowerSupplyRedundancy::Status::inProgress:
                    return ipmi::responseSuccess(parameter,
                                                 static_cast<uint8_t>(1));

                case server::PowerSupplyRedundancy::Status::completed:
                    return ipmi::responseSuccess(parameter,
                                                 static_cast<uint8_t>(0));
                default:
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "Error to get valid status");
                    return ipmi::responseResponseError();
            }
        }
        case crParameter::crFeature:
        {
            if (getCRConfig(ctx, "PowerSupplyRedundancyEnabled", value))
            {
                return ipmi::responseResponseError();
            }
            bool* pResponse = std::get_if<bool>(&value);
            if (!pResponse)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error to get PowerSupplyRedundancyEnabled property");
                return ipmi::responseResponseError();
            }

            return ipmi::responseSuccess(parameter,
                                         static_cast<uint8_t>(*pResponse));
        }
        case crParameter::rotationFeature:
        {
            if (getCRConfig(ctx, "RotationEnabled", value))
            {
                return ipmi::responseResponseError();
            }
            bool* pResponse = std::get_if<bool>(&value);
            if (!pResponse)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error to get RotationEnabled property");
                return ipmi::responseResponseError();
            }
            return ipmi::responseSuccess(parameter,
                                         static_cast<uint8_t>(*pResponse));
        }
        case crParameter::rotationAlgo:
        {
            if (getCRConfig(ctx, "RotationAlgorithm", value))
            {
                return ipmi::responseResponseError();
            }

            std::string* pAlgo = std::get_if<std::string>(&value);
            if (!pAlgo)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error to get RotationAlgorithm property");
                return ipmi::responseResponseError();
            }
            std::vector<uint8_t> response;
            namespace server = sdbusplus::xyz::openbmc_project::Control::server;
            auto algo =
                server::PowerSupplyRedundancy::convertAlgoFromString(*pAlgo);

            switch (algo)
            {
                case server::PowerSupplyRedundancy::Algo::bmcSpecific:
                    response.push_back(0);
                    break;
                case server::PowerSupplyRedundancy::Algo::userSpecific:
                    response.push_back(1);
                    break;
                default:
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "Error to get valid algo");
                    return ipmi::responseResponseError();
            }

            if (getCRConfig(ctx, "RotationRankOrder", value))
            {
                return ipmi::responseResponseError();
            }
            std::vector<uint8_t>* pResponse =
                std::get_if<std::vector<uint8_t>>(&value);
            if (!pResponse)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error to get RotationRankOrder property");
                return ipmi::responseResponseError();
            }

            std::copy(pResponse->begin(), pResponse->end(),
                      std::back_inserter(response));

            return ipmi::responseSuccess(parameter, response);
        }
        case crParameter::rotationPeriod:
        {
            if (getCRConfig(ctx, "PeriodOfRotation", value))
            {
                return ipmi::responseResponseError();
            }
            uint32_t* pResponse = std::get_if<uint32_t>(&value);
            if (!pResponse)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error to get RotationAlgorithm property");
                return ipmi::responseResponseError();
            }
            return ipmi::responseSuccess(parameter, *pResponse);
        }
        case crParameter::numOfPSU:
        {
            uint8_t numberOfPSU = getPSUCount();
            if (!numberOfPSU)
            {
                return ipmi::responseResponseError();
            }
            return ipmi::responseSuccess(parameter, numberOfPSU);
        }
        case crParameter::rotationRankOrderEffective:
        {
            if (getCRConfig(ctx, "RotationRankOrder", value,
                            "xyz.openbmc_project.PSURedundancy"))
            {
                return ipmi::responseResponseError();
            }
            std::vector<uint8_t>* pResponse =
                std::get_if<std::vector<uint8_t>>(&value);
            if (!pResponse)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error to get effective RotationRankOrder property");
                return ipmi::responseResponseError();
            }
            return ipmi::responseSuccess(parameter, *pResponse);
        }
        default:
        {
            return ipmi::response(ccParameterNotSupported);
        }
    }
}

ipmi::RspType<> ipmiOEMSetFaultIndication(
    uint8_t sourceId, uint8_t faultType, uint8_t faultState, uint8_t faultGroup,
    std::array<uint8_t, 8>& ledStateData)
{
    constexpr auto maxFaultType = static_cast<size_t>(RemoteFaultType::max);
    static const std::array<std::string, maxFaultType> faultNames = {
        "faultFan",       "faultTemp",     "faultPower",
        "faultDriveSlot", "faultSoftware", "faultMemory"};

    constexpr uint8_t maxFaultSource = 0x4;
    constexpr uint8_t skipLEDs = 0xFF;
    constexpr uint8_t pinSize = 64;
    constexpr uint8_t groupSize = 16;
    constexpr uint8_t groupNum = 5; // 4 for fault memory, 1 for faultFan

    // same pin names need to be defined in dts file
    static const std::array<std::array<std::string, groupSize>, groupNum>
        faultLedPinNames = {{
            "LED_CPU1_CH1_DIMM1_FAULT",
            "LED_CPU1_CH1_DIMM2_FAULT",
            "LED_CPU1_CH2_DIMM1_FAULT",
            "LED_CPU1_CH2_DIMM2_FAULT",
            "LED_CPU1_CH3_DIMM1_FAULT",
            "LED_CPU1_CH3_DIMM2_FAULT",
            "LED_CPU1_CH4_DIMM1_FAULT",
            "LED_CPU1_CH4_DIMM2_FAULT",
            "LED_CPU1_CH5_DIMM1_FAULT",
            "LED_CPU1_CH5_DIMM2_FAULT",
            "LED_CPU1_CH6_DIMM1_FAULT",
            "LED_CPU1_CH6_DIMM2_FAULT",
            "",
            "",
            "",
            "", // end of group1
            "LED_CPU2_CH1_DIMM1_FAULT",
            "LED_CPU2_CH1_DIMM2_FAULT",
            "LED_CPU2_CH2_DIMM1_FAULT",
            "LED_CPU2_CH2_DIMM2_FAULT",
            "LED_CPU2_CH3_DIMM1_FAULT",
            "LED_CPU2_CH3_DIMM2_FAULT",
            "LED_CPU2_CH4_DIMM1_FAULT",
            "LED_CPU2_CH4_DIMM2_FAULT",
            "LED_CPU2_CH5_DIMM1_FAULT",
            "LED_CPU2_CH5_DIMM2_FAULT",
            "LED_CPU2_CH6_DIMM1_FAULT",
            "LED_CPU2_CH6_DIMM2_FAULT",
            "",
            "",
            "",
            "", // endof group2
            "LED_CPU3_CH1_DIMM1_FAULT",
            "LED_CPU3_CH1_DIMM2_FAULT",
            "LED_CPU3_CH2_DIMM1_FAULT",
            "LED_CPU3_CH2_DIMM2_FAULT",
            "LED_CPU3_CH3_DIMM1_FAULT",
            "LED_CPU3_CH3_DIMM2_FAULT",
            "LED_CPU3_CH4_DIMM1_FAULT",
            "LED_CPU3_CH4_DIMM2_FAULT",
            "LED_CPU3_CH5_DIMM1_FAULT",
            "LED_CPU3_CH5_DIMM2_FAULT",
            "LED_CPU3_CH6_DIMM1_FAULT",
            "LED_CPU3_CH6_DIMM2_FAULT",
            "",
            "",
            "",
            "", // end of group3
            "LED_CPU4_CH1_DIMM1_FAULT",
            "LED_CPU4_CH1_DIMM2_FAULT",
            "LED_CPU4_CH2_DIMM1_FAULT",
            "LED_CPU4_CH2_DIMM2_FAULT",
            "LED_CPU4_CH3_DIMM1_FAULT",
            "LED_CPU4_CH3_DIMM2_FAULT",
            "LED_CPU4_CH4_DIMM1_FAULT",
            "LED_CPU4_CH4_DIMM2_FAULT",
            "LED_CPU4_CH5_DIMM1_FAULT",
            "LED_CPU4_CH5_DIMM2_FAULT",
            "LED_CPU4_CH6_DIMM1_FAULT",
            "LED_CPU4_CH6_DIMM2_FAULT",
            "",
            "",
            "",
            "", // end of group4
            "LED_FAN1_FAULT",
            "LED_FAN2_FAULT",
            "LED_FAN3_FAULT",
            "LED_FAN4_FAULT",
            "LED_FAN5_FAULT",
            "LED_FAN6_FAULT",
            "LED_FAN7_FAULT",
            "LED_FAN8_FAULT",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "" // end of group5
        }};

    // Validate the source, fault type --
    // (Byte 1) sourceId: Unspecified, Hot-Swap Controller 0, Hot-Swap
    // Controller 1, BIOS (Byte 2) fault type: fan, temperature, power,
    // driveslot, software, memory (Byte 3) FaultState: OK, Degraded,
    // Non-Critical, Critical, Non-Recoverable, (Byte 4) is faultGroup,
    // definition differs based on fault type (Byte 2)
    //          Type Fan=> Group: 0=FanGroupID, FF-not used
    //                  Byte 5-11 00h, not used
    //                  Byte12 FanLedState [7:0]-Fans 7:0
    //          Type Memory=> Group: 0 = DIMM GroupID, FF-not used
    //                  Byte 5:12 - DIMM LED state (64bit field, LS Byte first)
    //                  [63:48] = CPU4 channels 7:0, 2 bits per channel
    //                  [47:32] = CPU3 channels 7:0, 2 bits per channel
    //                  [31:16] = CPU2 channels 7:0, 2 bits per channel
    //                  [15:0] =  CPU1 channels 7:0, 2 bits per channel
    //          Type Other=> Component Fault LED Group ID, not used set to 0xFF
    //                  Byte[5:12]: reserved 0x00h
    if ((sourceId >= maxFaultSource) ||
        (faultType >= static_cast<int8_t>(RemoteFaultType::max)) ||
        (faultState >= static_cast<int8_t>(RemoteFaultState::maxFaultState)) ||
        (faultGroup >= static_cast<int8_t>(DimmFaultType::maxFaultGroup)))
    {
        return ipmi::responseParmOutOfRange();
    }

    size_t pinGroupOffset = 0;
    size_t pinGroupMax = pinSize / groupSize;
    if (RemoteFaultType::fan == RemoteFaultType(faultType))
    {
        pinGroupOffset = 4;
        pinGroupMax = groupNum - pinSize / groupSize;
    }

    switch (RemoteFaultType(faultType))
    {
        case (RemoteFaultType::fan):
        case (RemoteFaultType::memory):
        {
            if (faultGroup == skipLEDs)
            {
                return ipmi::responseSuccess();
            }
            // calculate led state bit filed count, each byte has 8bits
            // the maximum bits will be 8 * 8 bits
            constexpr uint8_t size = sizeof(ledStateData) * 8;

            // assemble ledState
            uint64_t ledState = 0;
            bool hasError = false;
            for (size_t i = 0; i < sizeof(ledStateData); i++)
            {
                ledState = (uint64_t)(ledState << 8);
                ledState = (uint64_t)(ledState | (uint64_t)ledStateData[i]);
            }
            std::bitset<size> ledStateBits(ledState);

            for (size_t group = 0; group < pinGroupMax; group++)
            {
                for (int i = 0; i < groupSize; i++)
                { // skip non-existing pins
                    if (0 == faultLedPinNames[group + pinGroupOffset][i].size())
                    {
                        continue;
                    }

                    gpiod::line line = gpiod::find_line(
                        faultLedPinNames[group + pinGroupOffset][i]);
                    if (!line)
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "Not Find Led Gpio Device!",
                            phosphor::logging::entry(
                                "DEVICE=%s",
                                faultLedPinNames[group + pinGroupOffset][i]
                                    .c_str()));
                        hasError = true;
                        continue;
                    }

                    bool activeHigh =
                        (line.active_state() == gpiod::line::ACTIVE_HIGH);
                    try
                    {
                        line.request(
                            {"faultLed", gpiod::line_request::DIRECTION_OUTPUT,
                             activeHigh
                                 ? 0
                                 : gpiod::line_request::FLAG_ACTIVE_LOW});
                        line.set_value(ledStateBits[i + group * groupSize]);
                    }
                    catch (const std::system_error&)
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "Error write Led Gpio Device!",
                            phosphor::logging::entry(
                                "DEVICE=%s",
                                faultLedPinNames[group + pinGroupOffset][i]
                                    .c_str()));
                        hasError = true;
                        continue;
                    }
                } // for int i
            }
            if (hasError)
            {
                return ipmi::responseResponseError();
            }
            break;
        }
        default:
        {
            // now only support two fault types
            return ipmi::responseParmOutOfRange();
        }
    } // switch
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiOEMReadBoardProductId()
{
    uint8_t prodId = 0;
    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        const DbusObjectInfo& object = getDbusObject(
            *dbus, "xyz.openbmc_project.Inventory.Item.Board",
            "/xyz/openbmc_project/inventory/system/board/", "Baseboard");
        const Value& propValue = getDbusProperty(
            *dbus, object.second, object.first,
            "xyz.openbmc_project.Inventory.Item.Board.Motherboard",
            "ProductId");
        prodId = static_cast<uint8_t>(std::get<uint64_t>(propValue));
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMReadBoardProductId: Product ID read failed!",
            phosphor::logging::entry("ERR=%s", e.what()));
    }
    return ipmi::responseSuccess(prodId);
}

/** @brief implements the get security mode command
 *  @param ctx - ctx pointer
 *
 *  @returns IPMI completion code with following data
 *   - restriction mode value - As specified in
 * xyz.openbmc_project.Control.Security.RestrictionMode.interface.yaml
 *   - special mode value - As specified in
 * xyz.openbmc_project.Control.Security.SpecialMode.interface.yaml
 */
ipmi::RspType<uint8_t, uint8_t> ipmiGetSecurityMode(ipmi::Context::ptr& ctx)
{
    namespace securityNameSpace =
        sdbusplus::xyz::openbmc_project::Control::Security::server;
    uint8_t restrictionModeValue = 0;
    uint8_t specialModeValue = 0;

    boost::system::error_code ec;
    auto varRestrMode = ctx->bus->yield_method_call<ipmi::DbusVariant>(
        ctx->yield, ec, restricionModeService, restricionModeBasePath,
        dBusPropertyIntf, dBusPropertyGetMethod, restricionModeIntf,
        restricionModeProperty);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiGetSecurityMode: failed to get RestrictionMode property",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        return ipmi::responseUnspecifiedError();
    }
    restrictionModeValue = static_cast<uint8_t>(
        securityNameSpace::RestrictionMode::convertModesFromString(
            std::get<std::string>(varRestrMode)));
    auto varSpecialMode = ctx->bus->yield_method_call<ipmi::DbusVariant>(
        ctx->yield, ec, specialModeService, specialModeBasePath,
        dBusPropertyIntf, dBusPropertyGetMethod, specialModeIntf,
        specialModeProperty);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiGetSecurityMode: failed to get SpecialMode property",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        // fall through, let us not worry about SpecialMode property, which is
        // not required in user scenario
    }
    else
    {
        specialModeValue = static_cast<uint8_t>(
            securityNameSpace::SpecialMode::convertModesFromString(
                std::get<std::string>(varSpecialMode)));
    }
    return ipmi::responseSuccess(restrictionModeValue, specialModeValue);
}

/** @brief implements the set security mode command
 *  Command allows to upgrade the restriction mode and won't allow
 *  to downgrade from system interface
 *  @param ctx - ctx pointer
 *  @param restrictionMode - restriction mode value to be set.
 *
 *  @returns IPMI completion code
 */
ipmi::RspType<> ipmiSetSecurityMode(ipmi::Context::ptr& ctx,
                                    uint8_t restrictionMode,
                                    std::optional<uint8_t> specialMode)
{
#ifndef BMC_VALIDATION_UNSECURE_FEATURE
    if (specialMode)
    {
        return ipmi::responseReqDataLenInvalid();
    }
#endif
    namespace securityNameSpace =
        sdbusplus::xyz::openbmc_project::Control::Security::server;

    ChannelInfo chInfo;
    if (getChannelInfo(ctx->channel, chInfo) != ccSuccess)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSetSecurityMode: Failed to get Channel Info",
            phosphor::logging::entry("CHANNEL=%d", ctx->channel));
        return ipmi::responseUnspecifiedError();
    }
    auto reqMode =
        static_cast<securityNameSpace::RestrictionMode::Modes>(restrictionMode);

    if ((reqMode < securityNameSpace::RestrictionMode::Modes::Provisioning) ||
        (reqMode >
         securityNameSpace::RestrictionMode::Modes::ProvisionedHostDisabled))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    boost::system::error_code ec;
    auto varRestrMode = ctx->bus->yield_method_call<ipmi::DbusVariant>(
        ctx->yield, ec, restricionModeService, restricionModeBasePath,
        dBusPropertyIntf, dBusPropertyGetMethod, restricionModeIntf,
        restricionModeProperty);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSetSecurityMode: failed to get RestrictionMode property",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        return ipmi::responseUnspecifiedError();
    }
    auto currentRestrictionMode =
        securityNameSpace::RestrictionMode::convertModesFromString(
            std::get<std::string>(varRestrMode));

    if (chInfo.mediumType !=
            static_cast<uint8_t>(EChannelMediumType::lan8032) &&
        currentRestrictionMode > reqMode)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSetSecurityMode - Downgrading security mode not supported "
            "through system interface",
            phosphor::logging::entry(
                "CUR_MODE=%d", static_cast<uint8_t>(currentRestrictionMode)),
            phosphor::logging::entry("REQ_MODE=%d", restrictionMode));
        return ipmi::responseCommandNotAvailable();
    }

    ec.clear();
    ctx->bus->yield_method_call<>(
        ctx->yield, ec, restricionModeService, restricionModeBasePath,
        dBusPropertyIntf, dBusPropertySetMethod, restricionModeIntf,
        restricionModeProperty,
        static_cast<ipmi::DbusVariant>(
            securityNameSpace::convertForMessage(reqMode)));

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSetSecurityMode: failed to set RestrictionMode property",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        return ipmi::responseUnspecifiedError();
    }

#ifdef BMC_VALIDATION_UNSECURE_FEATURE
    if (specialMode)
    {
        constexpr uint8_t mfgMode = 0x01;
        // Manufacturing mode is reserved. So can't enable this mode.
        if (specialMode.value() == mfgMode)
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "ipmiSetSecurityMode: Can't enable Manufacturing mode");
            return ipmi::responseInvalidFieldRequest();
        }

        ec.clear();
        ctx->bus->yield_method_call<>(
            ctx->yield, ec, specialModeService, specialModeBasePath,
            dBusPropertyIntf, dBusPropertySetMethod, specialModeIntf,
            specialModeProperty,
            static_cast<ipmi::DbusVariant>(securityNameSpace::convertForMessage(
                static_cast<securityNameSpace::SpecialMode::Modes>(
                    specialMode.value()))));

        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiSetSecurityMode: failed to set SpecialMode property",
                phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
            return ipmi::responseUnspecifiedError();
        }
    }
#endif
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t /* restore status */> ipmiRestoreConfiguration(
    const std::array<uint8_t, 3>& clr, uint8_t cmd)
{
    static constexpr std::array<uint8_t, 3> expClr = {'C', 'L', 'R'};

    if (clr != expClr)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    constexpr uint8_t cmdStatus = 0;
    constexpr uint8_t cmdDefaultRestore = 0xaa;
    constexpr uint8_t cmdFullRestore = 0xbb;
    constexpr uint8_t cmdFormat = 0xcc;

    constexpr const char* restoreOpFname = "/tmp/.rwfs/.restore_op";

    switch (cmd)
    {
        case cmdStatus:
            break;
        case cmdDefaultRestore:
        case cmdFullRestore:
        case cmdFormat:
        {
            // write file to rwfs root
            int value = (cmd - 1) & 0x03; // map aa, bb, cc => 1, 2, 3
            std::ofstream restoreFile(restoreOpFname);
            if (!restoreFile)
            {
                return ipmi::responseUnspecifiedError();
            }
            restoreFile << value << "\n";

            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "Restore to default will be performed on next BMC boot",
                phosphor::logging::entry("ACTION=0x%0X", cmd));

            break;
        }
        default:
            return ipmi::responseInvalidFieldRequest();
    }

    constexpr uint8_t restorePending = 0;
    constexpr uint8_t restoreComplete = 1;

    uint8_t restoreStatus = std::filesystem::exists(restoreOpFname)
                                ? restorePending
                                : restoreComplete;
    return ipmi::responseSuccess(restoreStatus);
}

ipmi::RspType<uint8_t> ipmiOEMGetNmiSource(void)
{
    uint8_t bmcSource;
    namespace nmi = sdbusplus::xyz::openbmc_project::Chassis::Control::server;

    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service =
            getService(*dbus, oemNmiSourceIntf, oemNmiSourceObjPath);
        Value variant =
            getDbusProperty(*dbus, service, oemNmiSourceObjPath,
                            oemNmiSourceIntf, oemNmiBmcSourceObjPathProp);

        switch (nmi::NMISource::convertBMCSourceSignalFromString(
            std::get<std::string>(variant)))
        {
            case nmi::NMISource::BMCSourceSignal::None:
                bmcSource = static_cast<uint8_t>(NmiSource::none);
                break;
            case nmi::NMISource::BMCSourceSignal::FrontPanelButton:
                bmcSource = static_cast<uint8_t>(NmiSource::frontPanelButton);
                break;
            case nmi::NMISource::BMCSourceSignal::Watchdog:
                bmcSource = static_cast<uint8_t>(NmiSource::watchdog);
                break;
            case nmi::NMISource::BMCSourceSignal::ChassisCmd:
                bmcSource = static_cast<uint8_t>(NmiSource::chassisCmd);
                break;
            case nmi::NMISource::BMCSourceSignal::MemoryError:
                bmcSource = static_cast<uint8_t>(NmiSource::memoryError);
                break;
            case nmi::NMISource::BMCSourceSignal::PciBusError:
                bmcSource = static_cast<uint8_t>(NmiSource::pciBusError);
                break;
            case nmi::NMISource::BMCSourceSignal::PCH:
                bmcSource = static_cast<uint8_t>(NmiSource::pch);
                break;
            case nmi::NMISource::BMCSourceSignal::Chipset:
                bmcSource = static_cast<uint8_t>(NmiSource::chipset);
                break;
            default:
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "NMI source: invalid property!",
                    phosphor::logging::entry(
                        "PROP=%s", std::get<std::string>(variant).c_str()));
                return ipmi::responseResponseError();
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(bmcSource);
}

ipmi::RspType<> ipmiOEMSetNmiSource(uint8_t sourceId)
{
    namespace nmi = sdbusplus::xyz::openbmc_project::Chassis::Control::server;

    nmi::NMISource::BMCSourceSignal bmcSourceSignal =
        nmi::NMISource::BMCSourceSignal::None;

    switch (NmiSource(sourceId))
    {
        case NmiSource::none:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::None;
            break;
        case NmiSource::frontPanelButton:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::FrontPanelButton;
            break;
        case NmiSource::watchdog:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::Watchdog;
            break;
        case NmiSource::chassisCmd:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::ChassisCmd;
            break;
        case NmiSource::memoryError:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::MemoryError;
            break;
        case NmiSource::pciBusError:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::PciBusError;
            break;
        case NmiSource::pch:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::PCH;
            break;
        case NmiSource::chipset:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::Chipset;
            break;
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "NMI source: invalid property!");
            return ipmi::responseResponseError();
    }

    try
    {
        // keep NMI signal source
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service =
            getService(*dbus, oemNmiSourceIntf, oemNmiSourceObjPath);
        setDbusProperty(*dbus, service, oemNmiSourceObjPath, oemNmiSourceIntf,
                        oemNmiBmcSourceObjPathProp,
                        nmi::convertForMessage(bmcSourceSignal));
        // set Enabled property to inform NMI source handling
        // to trigger a NMI_OUT BSOD.
        // if it's triggered by NMI source property changed,
        // NMI_OUT BSOD could be missed if the same source occurs twice in a row
        if (bmcSourceSignal != nmi::NMISource::BMCSourceSignal::None)
        {
            setDbusProperty(*dbus, service, oemNmiSourceObjPath,
                            oemNmiSourceIntf, oemNmiEnabledObjPathProp,
                            static_cast<bool>(true));
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess();
}

namespace dimmOffset
{
constexpr const char* dimmPower = "DimmPower";
constexpr const char* staticCltt = "StaticCltt";
constexpr const char* offsetPath = "/xyz/openbmc_project/Inventory/Item/Dimm";
constexpr const char* offsetInterface =
    "xyz.openbmc_project.Inventory.Item.Dimm.Offset";
constexpr const char* property = "DimmOffset";

}; // namespace dimmOffset

ipmi::RspType<> ipmiOEMSetDimmOffset(
    uint8_t type, const std::vector<std::tuple<uint8_t, uint8_t>>& data)
{
    if (type != static_cast<uint8_t>(dimmOffsetTypes::dimmPower) &&
        type != static_cast<uint8_t>(dimmOffsetTypes::staticCltt))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (data.empty())
    {
        return ipmi::responseInvalidFieldRequest();
    }
    nlohmann::json json;

    std::ifstream jsonStream(dimmOffsetFile);
    if (jsonStream.good())
    {
        json = nlohmann::json::parse(jsonStream, nullptr, false);
        if (json.is_discarded())
        {
            json = nlohmann::json();
        }
        jsonStream.close();
    }

    std::string typeName;
    if (type == static_cast<uint8_t>(dimmOffsetTypes::dimmPower))
    {
        typeName = dimmOffset::dimmPower;
    }
    else
    {
        typeName = dimmOffset::staticCltt;
    }

    nlohmann::json& field = json[typeName];

    for (const auto& [index, value] : data)
    {
        field[index] = value;
    }

    for (nlohmann::json& val : field)
    {
        if (val == nullptr)
        {
            val = static_cast<uint8_t>(0);
        }
    }

    std::ofstream output(dimmOffsetFile);
    if (!output.good())
    {
        std::cerr << "Error writing json file\n";
        return ipmi::responseResponseError();
    }

    output << json.dump(4);

    if (type == static_cast<uint8_t>(dimmOffsetTypes::staticCltt))
    {
        std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();

        ipmi::DbusVariant offsets = field.get<std::vector<uint8_t>>();
        auto call = bus->new_method_call(
            settingsBusName, dimmOffset::offsetPath, PROP_INTF, "Set");
        call.append(dimmOffset::offsetInterface, dimmOffset::property, offsets);
        try
        {
            bus->call(call);
        }
        catch (const sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetDimmOffset: can't set dimm offsets!",
                phosphor::logging::entry("ERR=%s", e.what()));
            return ipmi::responseResponseError();
        }
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiOEMGetDimmOffset(uint8_t type, uint8_t index)
{
    if (type != static_cast<uint8_t>(dimmOffsetTypes::dimmPower) &&
        type != static_cast<uint8_t>(dimmOffsetTypes::staticCltt))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::ifstream jsonStream(dimmOffsetFile);

    auto json = nlohmann::json::parse(jsonStream, nullptr, false);
    if (json.is_discarded())
    {
        std::cerr << "File error in " << dimmOffsetFile << "\n";
        return ipmi::responseResponseError();
    }

    std::string typeName;
    if (type == static_cast<uint8_t>(dimmOffsetTypes::dimmPower))
    {
        typeName = dimmOffset::dimmPower;
    }
    else
    {
        typeName = dimmOffset::staticCltt;
    }

    auto it = json.find(typeName);
    if (it == json.end())
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (it->size() <= index)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    uint8_t resp = it->at(index).get<uint8_t>();
    return ipmi::responseSuccess(resp);
}

namespace boot_options
{

using namespace sdbusplus::xyz::openbmc_project::Control::Boot::server;
using IpmiValue = uint8_t;
constexpr auto ipmiDefault = 0;

std::map<IpmiValue, Source::Sources> sourceIpmiToDbus = {
    {0x01, Source::Sources::Network},
    {0x02, Source::Sources::Disk},
    {0x05, Source::Sources::ExternalMedia},
    {0x0f, Source::Sources::RemovableMedia},
    {ipmiDefault, Source::Sources::Default}};

std::map<IpmiValue, Mode::Modes> modeIpmiToDbus = {
    {0x06, Mode::Modes::Setup}, {ipmiDefault, Mode::Modes::Regular}};

std::map<Source::Sources, IpmiValue> sourceDbusToIpmi = {
    {Source::Sources::Network, 0x01},
    {Source::Sources::Disk, 0x02},
    {Source::Sources::ExternalMedia, 0x05},
    {Source::Sources::RemovableMedia, 0x0f},
    {Source::Sources::Default, ipmiDefault}};

std::map<Mode::Modes, IpmiValue> modeDbusToIpmi = {
    {Mode::Modes::Setup, 0x06}, {Mode::Modes::Regular, ipmiDefault}};

static constexpr auto bootModeIntf = "xyz.openbmc_project.Control.Boot.Mode";
static constexpr auto bootSourceIntf =
    "xyz.openbmc_project.Control.Boot.Source";
static constexpr auto enabledIntf = "xyz.openbmc_project.Object.Enable";
static constexpr auto bootObjPath = "/xyz/openbmc_project/control/host0/boot";
static constexpr auto oneTimePath =
    "/xyz/openbmc_project/control/host0/boot/one_time";
static constexpr auto bootSourceProp = "BootSource";
static constexpr auto bootModeProp = "BootMode";
static constexpr auto oneTimeBootEnableProp = "Enabled";
static constexpr auto httpBootMode =
    "xyz.openbmc_project.Control.Boot.Source.Sources.Http";

enum class BootOptionParameter : size_t
{
    setInProgress = 0x0,
    bootFlags = 0x5,
};
static constexpr uint8_t setComplete = 0x0;
static constexpr uint8_t setInProgress = 0x1;
static uint8_t transferStatus = setComplete;
static constexpr uint8_t setParmVersion = 0x01;
static constexpr uint8_t setParmBootFlagsPermanent = 0x40;
static constexpr uint8_t setParmBootFlagsValidOneTime = 0x80;
static constexpr uint8_t setParmBootFlagsValidPermanent = 0xC0;
static constexpr uint8_t httpBoot = 0xd;
static constexpr uint8_t bootSourceMask = 0x3c;

} // namespace boot_options

ipmi::RspType<uint8_t,               // version
              uint8_t,               // param
              uint8_t,               // data0, dependent on parameter
              std::optional<uint8_t> // data1, dependent on parameter
              >
    ipmiOemGetEfiBootOptions(uint8_t parameter, [[maybe_unused]] uint8_t set,
                             [[maybe_unused]] uint8_t block)
{
    using namespace boot_options;
    uint8_t bootOption = 0;

    if (parameter == static_cast<uint8_t>(BootOptionParameter::setInProgress))
    {
        return ipmi::responseSuccess(setParmVersion, parameter, transferStatus,
                                     std::nullopt);
    }

    if (parameter != static_cast<uint8_t>(BootOptionParameter::bootFlags))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unsupported parameter");
        return ipmi::response(ccParameterNotSupported);
    }

    try
    {
        auto oneTimeEnabled = false;
        // read one time Enabled property
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service = getService(*dbus, enabledIntf, oneTimePath);
        Value variant = getDbusProperty(*dbus, service, oneTimePath,
                                        enabledIntf, oneTimeBootEnableProp);
        oneTimeEnabled = std::get<bool>(variant);

        service = getService(*dbus, bootModeIntf, bootObjPath);
        variant = getDbusProperty(*dbus, service, bootObjPath, bootModeIntf,
                                  bootModeProp);

        auto bootMode =
            Mode::convertModesFromString(std::get<std::string>(variant));

        service = getService(*dbus, bootSourceIntf, bootObjPath);
        variant = getDbusProperty(*dbus, service, bootObjPath, bootSourceIntf,
                                  bootSourceProp);

        if (std::get<std::string>(variant) == httpBootMode)
        {
            bootOption = httpBoot;
        }
        else
        {
            auto bootSource = Source::convertSourcesFromString(
                std::get<std::string>(variant));
            bootOption = sourceDbusToIpmi.at(bootSource);
            if (Source::Sources::Default == bootSource)
            {
                bootOption = modeDbusToIpmi.at(bootMode);
            }
        }

        uint8_t oneTime = oneTimeEnabled ? setParmBootFlagsValidOneTime
                                         : setParmBootFlagsValidPermanent;
        bootOption <<= 2; // shift for responseconstexpr
        return ipmi::responseSuccess(setParmVersion, parameter, oneTime,
                                     bootOption);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return ipmi::responseResponseError();
    }
}

ipmi::RspType<> ipmiOemSetEfiBootOptions(uint8_t bootFlag, uint8_t bootParam,
                                         std::optional<uint8_t> bootOption)
{
    using namespace boot_options;
    auto oneTimeEnabled = false;

    if (bootFlag == static_cast<uint8_t>(BootOptionParameter::setInProgress))
    {
        if (bootOption)
        {
            return ipmi::responseReqDataLenInvalid();
        }

        if (bootParam == setComplete)
        {
            transferStatus = setComplete;
        }
        else
        {
            transferStatus = bootParam;
        }

        return ipmi::responseSuccess();
    }
    if (bootFlag != (uint8_t)BootOptionParameter::bootFlags)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unsupported parameter");
        return ipmi::response(ccParameterNotSupported);
    }

    if (!bootOption)
    {
        return ipmi::responseReqDataLenInvalid();
    }

    if (((bootOption.value() & bootSourceMask) >> 2) !=
        httpBoot) // not http boot, exit
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "wrong boot option parameter!");
        return ipmi::responseParmOutOfRange();
    }

    try
    {
        bool permanent = (bootParam & setParmBootFlagsPermanent) ==
                         setParmBootFlagsPermanent;

        // read one time Enabled property
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service = getService(*dbus, enabledIntf, oneTimePath);
        Value variant = getDbusProperty(*dbus, service, oneTimePath,
                                        enabledIntf, oneTimeBootEnableProp);
        oneTimeEnabled = std::get<bool>(variant);

        /*
         * Check if the current boot setting is onetime or permanent, if the
         * request in the command is otherwise, then set the "Enabled"
         * property in one_time object path to 'True' to indicate onetime
         * and 'False' to indicate permanent.
         *
         * Once the onetime/permanent setting is applied, then the bootMode
         * and bootSource is updated for the corresponding object.
         */
        if (permanent == oneTimeEnabled)
        {
            setDbusProperty(*dbus, service, oneTimePath, enabledIntf,
                            oneTimeBootEnableProp, !permanent);
        }

        std::string bootMode =
            "xyz.openbmc_project.Control.Boot.Mode.Modes.Regular";
        std::string bootSource = httpBootMode;

        service = getService(*dbus, bootModeIntf, bootObjPath);
        setDbusProperty(*dbus, service, bootObjPath, bootModeIntf, bootModeProp,
                        bootMode);

        service = getService(*dbus, bootSourceIntf, bootObjPath);
        setDbusProperty(*dbus, service, bootObjPath, bootSourceIntf,
                        bootSourceProp, bootSource);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess();
}

using BasicVariantType = ipmi::DbusVariant;
using PropertyMapType =
    boost::container::flat_map<std::string, BasicVariantType>;
static constexpr const std::array<const char*, 1> psuPresenceTypes = {
    "xyz.openbmc_project.Configuration.PSUPresence"};
int getPSUAddress(ipmi::Context::ptr& ctx, uint8_t& bus,
                  std::vector<uint64_t>& addrTable)
{
    boost::system::error_code ec;
    GetSubTreeType subtree = ctx->bus->yield_method_call<GetSubTreeType>(
        ctx->yield, ec, "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree",
        "/xyz/openbmc_project/inventory/system", 3, psuPresenceTypes);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set dbus property to cold redundancy");
        return -1;
    }
    for (const auto& object : subtree)
    {
        std::string pathName = object.first;
        for (const auto& serviceIface : object.second)
        {
            std::string serviceName = serviceIface.first;

            ec.clear();
            PropertyMapType propMap =
                ctx->bus->yield_method_call<PropertyMapType>(
                    ctx->yield, ec, serviceName, pathName,
                    "org.freedesktop.DBus.Properties", "GetAll",
                    "xyz.openbmc_project.Configuration.PSUPresence");
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Failed to set dbus property to cold redundancy");
                return -1;
            }
            auto psuBus = std::get_if<uint64_t>(&propMap["Bus"]);
            auto psuAddress =
                std::get_if<std::vector<uint64_t>>(&propMap["Address"]);

            if (psuBus == nullptr || psuAddress == nullptr)
            {
                std::cerr << "error finding necessary "
                             "entry in configuration\n";
                return -1;
            }
            bus = static_cast<uint8_t>(*psuBus);
            addrTable = *psuAddress;
            return 0;
        }
    }
    return -1;
}

static const constexpr uint8_t addrOffset = 8;
static const constexpr uint8_t psuRevision = 0xd9;
static const constexpr uint8_t defaultPSUBus = 7;
// Second Minor, Primary Minor, Major
static const constexpr size_t verLen = 3;
ipmi::RspType<std::vector<uint8_t>> ipmiOEMGetPSUVersion(
    ipmi::Context::ptr& ctx)
{
    uint8_t bus = defaultPSUBus;
    std::vector<uint64_t> addrTable;
    std::vector<uint8_t> result;
    if (getPSUAddress(ctx, bus, addrTable))
    {
        std::cerr << "Failed to get PSU bus and address\n";
        return ipmi::responseResponseError();
    }

    for (const auto& targetAddr : addrTable)
    {
        std::vector<uint8_t> writeData = {psuRevision};
        std::vector<uint8_t> readBuf(verLen);
        uint8_t addr = static_cast<uint8_t>(targetAddr) + addrOffset;
        std::string i2cBus = "/dev/i2c-" + std::to_string(bus);

        auto retI2C = ipmi::i2cWriteRead(i2cBus, addr, writeData, readBuf);
        if (retI2C != ipmi::ccSuccess)
        {
            for (size_t idx = 0; idx < verLen; idx++)
            {
                result.emplace_back(0x00);
            }
        }
        else
        {
            for (const uint8_t& data : readBuf)
            {
                result.emplace_back(data);
            }
        }
    }

    return ipmi::responseSuccess(result);
}

std::optional<uint8_t> getMultiNodeInfoPresence(ipmi::Context::ptr& ctx,
                                                const std::string& name)
{
    Value dbusValue = 0;
    std::string serviceName;

    boost::system::error_code ec =
        ipmi::getService(ctx, multiNodeIntf, multiNodeObjPath, serviceName);

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to perform Multinode getService.");
        return std::nullopt;
    }

    ec = ipmi::getDbusProperty(ctx, serviceName, multiNodeObjPath,
                               multiNodeIntf, name, dbusValue);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to perform Multinode get property");
        return std::nullopt;
    }

    auto multiNodeVal = std::get_if<uint8_t>(&dbusValue);
    if (!multiNodeVal)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getMultiNodeInfoPresence: error to get multinode");
        return std::nullopt;
    }
    return *multiNodeVal;
}

/** @brief implements OEM get reading command
 *  @param domain ID
 *  @param reading Type
 *    - 00h = platform Power Consumption
 *    - 01h = inlet Air Temp
 *    - 02h = icc_TDC from PECI
 *  @param reserved, write as 0000h
 *
 *  @returns IPMI completion code plus response data
 *  - response
 *     - domain ID
 *     - reading Type
 *       - 00h = platform Power Consumption
 *       - 01h = inlet Air Temp
 *       - 02h = icc_TDC from PECI
 *     - reading
 */
ipmi::RspType<uint4_t, // domain ID
              uint4_t, // reading Type
              uint16_t // reading Value
              >
    ipmiOEMGetReading(ipmi::Context::ptr& ctx, uint4_t domainId,
                      uint4_t readingType, uint16_t reserved)
{
    [[maybe_unused]] constexpr uint8_t platformPower = 0;
    constexpr uint8_t inletAirTemp = 1;
    constexpr uint8_t iccTdc = 2;
    constexpr Cc ccSensorInvalid = 0xCB;

    if ((static_cast<uint8_t>(readingType) > iccTdc) || domainId || reserved)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // This command should run only from multi-node product.
    // For all other platforms this command will return invalid.

    /*std::optional<uint8_t> nodeInfo =
        getMultiNodeInfoPresence(ctx, "NodePresence");
    if (!nodeInfo || !*nodeInfo)
    {
        return ipmi::responseInvalidCommand();
    }*/

    uint16_t oemReadingValue = 0;
    if (static_cast<uint8_t>(readingType) == inletAirTemp)
    {
        double value = 0;
        boost::system::error_code ec = ipmi::getDbusProperty(
            ctx, "xyz.openbmc_project.HwmonTempSensor",
            "/xyz/openbmc_project/sensors/temperature/Inlet_BRD_Temp",
            "xyz.openbmc_project.Sensor.Value", "Value", value);
        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to get BMC Get OEM temperature",
                phosphor::logging::entry("EXCEPTION=%s", ec.message().c_str()));
            return ipmi::response(ccSensorInvalid);
        }
        // Take the Inlet temperature
        oemReadingValue = static_cast<uint16_t>(value);
    }
    else if (static_cast<uint8_t>(readingType) == platformPower) // plt power
    {
        double value = 0;
        boost::system::error_code ec = ipmi::getDbusProperty(
            ctx, "xyz.openbmc_project.IntelCPUSensor",
            "/xyz/openbmc_project/sensors/power/Platform_Power_Average_CPU1",
            "xyz.openbmc_project.Sensor.Value", "Value", value);
        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to get BMC Get Platform Power",
                phosphor::logging::entry("EXCEPTION=%s", ec.message().c_str()));
            return ipmi::response(ccSensorInvalid);
        }
        // Take the Platform Power
        oemReadingValue = static_cast<uint16_t>(value);
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Currently Get OEM Reading support only for Inlet Air Temp And Platform Power");
        return ipmi::responseParmOutOfRange();
    }
    return ipmi::responseSuccess(domainId, readingType, oemReadingValue);
}

/** @brief implements the maximum size of
 *  bridgeable messages used between KCS and
 *  IPMB interfacesget security mode command.
 *
 *  @returns IPMI completion code with following data
 *   - KCS Buffer Size (In multiples of four bytes)
 *   - IPMB Buffer Size (In multiples of four bytes)
 **/
ipmi::RspType<uint8_t, uint8_t> ipmiOEMGetBufferSize()
{
    // for now this is hard coded; really this number is dependent on
    // the BMC kcs driver as well as the host kcs driver....
    // we can't know the latter.
    uint8_t kcsMaxBufferSize = 63 / 4;
    uint8_t ipmbMaxBufferSize = 128 / 4;

    return ipmi::responseSuccess(kcsMaxBufferSize, ipmbMaxBufferSize);
}

bool setrecaddress(ipmi::Context::ptr ctx, std::string smtpIntf,
                   std::vector<std::string> rec)
{
    std::variant<std::vector<std::string>> variantVectorValue = rec;

    try
    {
        boost::system::error_code ec;
        ctx->bus->yield_method_call<void>(
            ctx->yield, ec, smtpclient, smtpObj, dBusPropertyIntf,
            dBusPropertySetMethod, smtpIntf, "Recipient", variantVectorValue);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set dbus property to Recipient");
        return false;
    }
    return true;
}

bool getrecaddress(ipmi::Context::ptr ctx, std::string smtpIntf,
                   std::vector<std::string>& rec)
{
    try
    {
        boost::system::error_code ec;
        auto recpAdd = ctx->bus->yield_method_call<ipmi::DbusVariant>(
            ctx->yield, ec, smtpclient, smtpObj, dBusPropertyIntf,
            dBusPropertyGetMethod, smtpIntf, "Recipient");
        rec = std::get<std::vector<std::string>>(recpAdd);
    }
    catch (const sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get Recipient Dbus property");
        return false;
    }

    return true;
}

bool emailIdCheck(std::string email)
{
    const std::regex pattern("(\\w+)(\\.|_)?(\\w*)@(\\w+)(\\.(\\w+))+");
    return std::regex_match(email, pattern);
}

template <typename T>
static T unpackT(ipmi::message::Payload& req)
{
    std::array<uint8_t, sizeof(T)> bytes;
    if (req.unpack(bytes) != 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Length of Data");
    }
    return stdplus::raw::copyFrom<T>(bytes);
};

RspType<> ipmiOEMSetSmtpConfig(ipmi::Context::ptr ctx, uint8_t server,
                               uint8_t parameter, message::Payload& req)
{
    bool mailChk = false;
    std::string smtpIntf{};
    std::vector<std::string> rec;
    if (static_cast<uint8_t>(server) ==
        static_cast<uint8_t>(ServerType::SMTP_PRIMARY))
    {
        smtpIntf = smtpPrimaryIntf;
    }
    else if (static_cast<uint8_t>(server) ==
             static_cast<uint8_t>(ServerType::SMTP_SECONDARY))
    {
        smtpIntf = smtpSecondaryIntf;
    }
    else
    {
        return ipmi::responseInvalidFieldRequest();
    }
    if (!(getrecaddress(ctx, smtpIntf, rec)))
    {
        return ipmi::responseUnspecifiedError();
    }
    switch (smtpSetting(parameter))
    {
        case smtpSetting::authentication:
        {
            bool Authentication{};
            uint7_t rsvd{};
            if (req.unpack(Authentication, rsvd) || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            if (rsvd != 0)
            {
                return responseInvalidFieldRequest();
            }
            if (ipmi::setDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Authentication", Authentication))
            {
                return responseUnspecifiedError();
            }
            return responseSuccess();
        }
        case smtpSetting::enable:
        {
            bool enable{};
            uint7_t rsvd{};
            if (req.unpack(enable, rsvd) || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            if (rsvd != 0)
            {
                return responseInvalidFieldRequest();
            }
            if (ipmi::setDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Enable", enable))
            {
                return responseUnspecifiedError();
            }
            return responseSuccess();
        }
        case smtpSetting::ipAdd:
        {
            std::array<uint8_t, 4> bytes;
            std::string host;
            if (req.unpack(bytes) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            host = std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) +
                   "." + std::to_string(bytes[2]) + "." +
                   std::to_string(bytes[3]);
            if (ipmi::setDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Host", host))
            {
                return responseUnspecifiedError();
            }
            return responseSuccess();
        }
        case smtpSetting::passWord:
        {
            std::vector<char> reqData;
            if (req.unpack(reqData) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            if (reqData.size() > 64)
            {
                return responseReqDataLenInvalid();
            }
            std::string password(reqData.begin(), reqData.end());
            if (ipmi::setDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Password", password))
            {
                return responseUnspecifiedError();
            }

            return responseSuccess();
        }
        case smtpSetting::port:
        {
            std::vector<uint8_t> bytes;
            if (req.unpack(bytes) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            if ((bytes.size() > 2) || (bytes.size() < 2))
            {
                return responseReqDataLenInvalid();
            }
            uint16_t smtpPort, smtpPortTmp;
            smtpPortTmp = bytes.at(0);
            smtpPort = ((smtpPortTmp << 8) | (bytes.at(1) & 0xff));
            if (ipmi::setDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Port", smtpPort))
            {
                return responseUnspecifiedError();
            }
            return responseSuccess();
        }
        case smtpSetting::recMailId:
        {
            uint8_t index = 0;
            std::vector<char> reqData;
            std::vector<std::string> recp;
            if (req.unpack(index, reqData) != 0)
            {
                return responseReqDataLenInvalid();
            }
            if (reqData.size() > 64)
            {
                return responseReqDataLenInvalid();
            }
            if ((index < min_recipient) || (index > max_recipient))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            std::string reci(reqData.begin(), reqData.end());
            mailChk = emailIdCheck(reci);
            if (mailChk == false)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            replace(rec.begin(), rec.end(), rec[index - 1], reci);
            if (!setrecaddress(ctx, smtpIntf, rec))
            {
                return ipmi::responseUnspecifiedError();
            }
            return responseSuccess();
        }
        case smtpSetting::senderMailId:
        {
            std::vector<char> reqData;
            if (req.unpack(reqData) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            if (reqData.size() > 64)
            {
                return responseReqDataLenInvalid();
            }
            std::string sender(reqData.begin(), reqData.end());
            mailChk = emailIdCheck(sender);
            if (mailChk == false)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            if (ipmi::setDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Sender", sender))
            {
                return responseUnspecifiedError();
            }
            return responseSuccess();
        }
        case smtpSetting::tlsEnable:
        {
            bool TLSEnable{};
            uint7_t rsvd{};
            if (req.unpack(TLSEnable, rsvd) || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            if (rsvd != 0)
            {
                return responseInvalidFieldRequest();
            }
            if (ipmi::setDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "TLSEnable", TLSEnable))
            {
                return responseUnspecifiedError();
            }
            return responseSuccess();
        }
        case smtpSetting::userName:
        {
            std::vector<char> reqData;
            if (req.unpack(reqData) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            if (reqData.size() > 64)
            {
                return responseReqDataLenInvalid();
            }
            std::string username(reqData.begin(), reqData.end());
            if (ipmi::setDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "UserName", username))
            {
                return responseUnspecifiedError();
            }
            return responseSuccess();
        }
        case smtpSetting::ipAddv6:
        {
            std::string host;
            auto ip = unpackT<stdplus::In6Addr>(req);
            if (!req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }
            if (!ipmi::utility::ip_address::isValidIPv6Addr(
                    (in6_addr*)(&ip.__in6_u),
                    ipmi::utility::ip_address::Type::IP6_ADDRESS))
            {
                return responseInvalidFieldRequest();
            }
            host = stdplus::toStr(stdplus::In6Addr{ip});
            if (ipmi::setDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Host", host))
            {
                return responseUnspecifiedError();
            }
            return responseSuccess();
        }
        default:
            return responseInvalidFieldRequest();
    }
    return responseSuccess();
}

std::vector<uint8_t> convertToBytes(std::string data)
{
    std::vector<uint8_t> val{};
    uint8_t byteData = 0;
    for (std::string::size_type i = 0; i < data.length(); i++)
    {
        byteData = data[i];
        val.push_back(byteData);
    }
    return val;
}

ipmi::RspType<message::Payload> ipmiOEMGetSmtpConfig(
    ipmi::Context::ptr ctx, uint8_t server, uint8_t parameter,
    message::Payload& req)
{
    message::Payload ret;
    std::string smtpIntf{};
    if (static_cast<uint8_t>(server) ==
        static_cast<uint8_t>(ServerType::SMTP_PRIMARY))
    {
        smtpIntf = smtpPrimaryIntf;
    }
    else if (static_cast<uint8_t>(server) ==
             static_cast<uint8_t>(ServerType::SMTP_SECONDARY))
    {
        smtpIntf = smtpSecondaryIntf;
    }
    else
    {
        return ipmi::responseInvalidFieldRequest();
    }
    std::vector<uint8_t> resData = {};
    if (parameter != static_cast<uint8_t>(smtpSetting ::recMailId))
    {
        std::array<uint8_t, 0> bytes;
        if (req.unpack(bytes) != 0 || !req.fullyUnpacked())
        {
            return responseReqDataLenInvalid();
        }
    }
    switch (smtpSetting(parameter))
    {
        case smtpSetting::authentication:
        {
            bool Authentication{};
            if (ipmi::getDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Authentication", Authentication))
            {
                return responseUnspecifiedError();
            }
            ret.pack(Authentication, uint7_t{});
            return responseSuccess(std::move(ret));
        }
        case smtpSetting::enable:
        {
            bool enable{};
            if (ipmi::getDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Enable", enable))
            {
                return responseUnspecifiedError();
            }
            ret.pack(enable, uint7_t{});
            return responseSuccess(std::move(ret));
        }
        case smtpSetting::ipAdd:
        {
            std::vector<std::string> result;
            std::string host;
            if (ipmi::getDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Host", host))
            {
                return responseUnspecifiedError();
            }
            if (!host.empty())
            {
                boost::split(result, host, boost::is_any_of("."),
                             boost::token_compress_on);
                uint8_t ipByte1 =
                    static_cast<uint8_t>(std::stoi(result[0].c_str()));
                uint8_t ipByte2 =
                    static_cast<uint8_t>(std::stoi(result[1].c_str()));
                uint8_t ipByte3 =
                    static_cast<uint8_t>(std::stoi(result[2].c_str()));
                uint8_t ipByte4 =
                    static_cast<uint8_t>(std::stoi(result[3].c_str()));
                resData.push_back(ipByte1);
                resData.push_back(ipByte2);
                resData.push_back(ipByte3);
                resData.push_back(ipByte4);
                ret.pack(resData);
                return responseSuccess(std::move(ret));
            }
            ret.pack(resData);
            return responseSuccess(std::move(ret));
        }
        case smtpSetting::passWord:
        {
            std::string password;
            if (ipmi::getDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Password", password))
            {
                return responseUnspecifiedError();
            }
            ret.pack(convertToBytes(password));
            return responseSuccess(std::move(ret));
        }
        case smtpSetting::port:
        {
            uint16_t port;
            if (ipmi::getDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Port", port))
            {
                return responseUnspecifiedError();
            }
            uint8_t portMsb = 0, portLsb = 0;
            portMsb = ((port >> 8) & 0xff);
            portLsb = (port & 0xff);
            resData.push_back(portMsb);
            resData.push_back(portLsb);
            ret.pack(resData);
            return responseSuccess(std::move(ret));
        }
        case smtpSetting::recMailId:
        {
            uint8_t index = 0;
            std::array<uint8_t, 0> bytes;
            std::vector<std::string> recipient;
            if (ipmi::getDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Recipient", recipient))
            {
                return responseUnspecifiedError();
            }

            if ((req.unpack(index, bytes) != 0) || (!req.fullyUnpacked()))
            {
                return responseReqDataLenInvalid();
            }

            if ((index < min_recipient) || (index > max_recipient))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            uint8_t size = recipient.size();
            if (index > size)
            {
                return ipmi::responseResponseError();
            }
            std::string str = recipient[index - 1];
            if (str.empty())
            {
                return ipmi::responseResponseError();
            }
            ret.pack(convertToBytes(str));
            return responseSuccess(std::move(ret));
        }
        case smtpSetting::senderMailId:
        {
            std::string sender;
            if (ipmi::getDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Sender", sender))
            {
                return responseUnspecifiedError();
            }
            ret.pack(convertToBytes(sender));
            return responseSuccess(std::move(ret));
        }
        case smtpSetting::tlsEnable:
        {
            bool tls{};
            if (ipmi::getDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "TLSEnable", tls))
            {
                return responseUnspecifiedError();
            }
            ret.pack(tls, uint7_t{});
            return responseSuccess(std::move(ret));
        }
        case smtpSetting::userName:
        {
            std::string username;
            if (ipmi::getDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "UserName", username))
            {
                return responseUnspecifiedError();
            }
            ret.pack(convertToBytes(username));
            return responseSuccess(std::move(ret));
        }
        case smtpSetting::ipAddv6:
        {
            std::string host;
            if (ipmi::getDbusProperty(ctx, smtpclient, smtpObj, smtpIntf,
                                      "Host", host))
            {
                return responseUnspecifiedError();
            }
            if (!host.empty())
            {
                stdplus::In6Addr addr{};
                addr = stdplus::fromStr<stdplus::In6Addr>(host);
                ret.pack(stdplus::raw::asView<char>(addr));
            }
            return responseSuccess(std::move(ret));
        }
        default:
            return ipmi::responseInvalidFieldRequest();
    }
    return ipmi::responseInvalidFieldRequest();
}

ipmi::RspType<std::vector<uint8_t>> ipmiOEMReadPFRMailbox(
    ipmi::Context::ptr& ctx, const uint8_t readRegister,
    const uint8_t numOfBytes, uint8_t registerIdentifier)
{
    if (!ipmi::mailbox::i2cConfigLoaded)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Calling PFR Load Configuration Function to Get I2C Bus and Target "
            "Address ");

        ipmi::mailbox::loadPfrConfig(ctx, ipmi::mailbox::i2cConfigLoaded);
    }

    if (!numOfBytes && !readRegister)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "OEM IPMI command: Read & write count are 0 which is invalid ");
        return ipmi::responseInvalidFieldRequest();
    }

    switch (registerIdentifier)
    {
        case ipmi::mailbox::registerType::fifoReadRegister:
        {
            // Check if readRegister is an FIFO read register
            if (ipmi::mailbox::readFifoReg.find(readRegister) ==
                ipmi::mailbox::readFifoReg.end())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "OEM IPMI command: Register is not a Read FIFO  ");
                return ipmi::responseInvalidFieldRequest();
            }

            phosphor::logging::log<phosphor::logging::level::ERR>(
                "OEM IPMI command: Register is a Read FIFO  ");

            ipmi::mailbox::writefifo(ipmi::mailbox::provisioningCommand,
                                     readRegister);
            ipmi::mailbox::writefifo(ipmi::mailbox::triggerCommand,
                                     ipmi::mailbox::flushRead);

            std::vector<uint8_t> writeData = {ipmi::mailbox::readFifo};
            std::vector<uint8_t> readBuf(1);
            std::vector<uint8_t> result;

            for (int i = 0; i < numOfBytes; i++)
            {
                ipmi::Cc ret = ipmi::i2cWriteRead(ipmi::mailbox::i2cBus,
                                                  ipmi::mailbox::targetAddr,
                                                  writeData, readBuf);
                if (ret != ipmi::ccSuccess)
                {
                    return ipmi::response(ret);
                }

                else
                {
                    for (const uint8_t& data : readBuf)
                    {
                        result.emplace_back(data);
                    }
                }
            }

            return ipmi::responseSuccess(result);
        }

        case ipmi::mailbox::registerType::singleByteRegister:
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "OEM IPMI command: Register is a Single Byte Register ");

            std::vector<uint8_t> writeData = {readRegister};
            std::vector<uint8_t> readBuf(numOfBytes);

            ipmi::Cc ret = ipmi::i2cWriteRead(ipmi::mailbox::i2cBus,
                                              ipmi::mailbox::targetAddr,
                                              writeData, readBuf);
            if (ret != ipmi::ccSuccess)
            {
                return ipmi::response(ret);
            }
            return ipmi::responseSuccess(readBuf);
        }

        default:
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "OEM IPMI command: Register identifier is not valid.It should "
                "be 0 "
                "for Single Byte Register and 1 for FIFO Read Register");

            return ipmi::responseInvalidFieldRequest();
        }
    }
}

int dateTimeCheck(std::string dateTime)
{
    std::vector<std::string> list, dateList, timeList;
    boost::split(list, dateTime, boost::is_any_of("T"),
                 boost::token_compress_on);
    boost::split(dateList, list.at(0), boost::is_any_of("-"),
                 boost::token_compress_on);
    boost::split(timeList, list.at(1), boost::is_any_of(":"),
                 boost::token_compress_on);

    // Check Date
    auto isLeap = [](int year) { return (year % 4) == 0 ? true : false; };

    if (std::stoi(dateList.at(1)) > 12 || std::stoi(dateList.at(1)) < 1)
    {
        return 1;
    }

    if (std::stoi(dateList.at(2)) < 1)
    {
        return 1;
    }

    if (std::stoi(dateList.at(1)) == 2)
    {
        if (isLeap(std::stoi(dateList.at(0))) && std::stoi(dateList.at(2)) > 29)
        {
            return 1;
        } // if
        else if (!isLeap(std::stoi(dateList.at(0))) &&
                 std::stoi(dateList.at(2)) > 28)
        {
            return 1;
        } // else if
    } // if

    if (std::stoi(dateList.at(1)) == 4 || std::stoi(dateList.at(1)) == 6 ||
        std::stoi(dateList.at(1)) == 9 || std::stoi(dateList.at(1)) == 11)
    {
        if (std::stoi(dateList.at(2)) > 30)
            return 1;
    } // if
    else if (std::stoi(dateList.at(1)) == 1 || std::stoi(dateList.at(1)) == 3 ||
             std::stoi(dateList.at(1)) == 5 || std::stoi(dateList.at(1)) == 7 ||
             std::stoi(dateList.at(1)) == 8 ||
             std::stoi(dateList.at(1)) == 10 || std::stoi(dateList.at(1)) == 12)
    {
        if (std::stoi(dateList.at(2)) > 31)
            return 1;
    } // else if

    // Check Time
    if (std::stoi(timeList.at(0)) < 0 || std::stoi(timeList.at(0)) > 23)
    {
        return -1;
    }
    if (std::stoi(timeList.at(1)) < 0 || std::stoi(timeList.at(1)) > 59)
    {
        return -1;
    }
    if (std::stoi(timeList.at(2)) < 0 || std::stoi(timeList.at(2)) > 59)
    {
        return -1;
    }

    return 0;
}

int dateTimeCompare(std::string date1, std::string date2)
{
    std::vector<std::string> dateTimeList1, dateTimeList2;
    std::vector<std::string> tmpList1, tmpList2;

    boost::split(tmpList1, date1, boost::is_any_of("T"),
                 boost::token_compress_on);
    boost::split(tmpList2, date2, boost::is_any_of("T"),
                 boost::token_compress_on);
    boost::split(dateTimeList1, tmpList1.at(0), boost::is_any_of("-"),
                 boost::token_compress_on);
    boost::split(dateTimeList2, tmpList2.at(0), boost::is_any_of("-"),
                 boost::token_compress_on);

    for (auto i = 0; i < (int)dateTimeList1.size(); i++)
    {
        if (std::stoi(dateTimeList1.at(i)) > std::stoi(dateTimeList2.at(i)))
            return -1;
    }

    dateTimeList1.clear();
    dateTimeList2.clear();
    boost::split(dateTimeList1, tmpList1.at(1), boost::is_any_of(":"),
                 boost::token_compress_on);
    boost::split(dateTimeList2, tmpList2.at(1), boost::is_any_of(":"),
                 boost::token_compress_on);

    for (auto i = 0; i < (int)dateTimeList1.size(); i++)
    {
        if (std::stoi(dateTimeList1.at(i)) > std::stoi(dateTimeList2.at(i)))
            return -1;
    }

    return 0;
}

ipmi::RspType<message::Payload> ipmiOEMSetFirewallConfiguration(
    uint8_t parameter, message::Payload& req)
{
    message::Payload ret;
    using FirewallIface =
        sdbusplus::xyz::openbmc_project::Network::server::FirewallConfiguration;
    static struct FirewallProperties
    {
        std::string target;
        uint8_t control;
        std::string protocol;
        std::string startIPAddr;
        std::string endIPAddr;
        uint16_t startPort;
        uint16_t endPort;
        std::string macAddr;
        std::string startTime;
        std::string endTime;
        std::string IPver;
    } properties;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    switch (static_cast<ami::general::network::SetFirewallOEMParam>(parameter))
    {
        case ami::general::network::SetFirewallOEMParam::PARAM_TARGET:
        {
            uint8_t target;
            if (req.unpack(target) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            try
            {
                properties.target = sdbusplus::xyz::openbmc_project::Network::
                    server::convertForMessage(
                        static_cast<FirewallIface::Target>(target));
            }
            catch (const std::exception& e)
            {
                return ipmi::responseInvalidFieldRequest();
            }

            return ipmi::responseSuccess();
        }
        case ami::general::network::SetFirewallOEMParam::PARAM_PROTOCOL:
        {
            uint8_t protocol;
            if (req.unpack(protocol) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            try
            {
                properties.protocol = sdbusplus::xyz::openbmc_project::Network::
                    server::convertForMessage(
                        static_cast<FirewallIface::Protocol>(protocol));
            }
            catch (const std::exception& e)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            properties.control |= static_cast<uint8_t>(
                ami::general::network::FirewallFlags::PROTOCOL);

            return ipmi::responseSuccess();
        }
        case ami::general::network::SetFirewallOEMParam::
            PARAM_START_SOURCE_IP_ADDR:
        case ami::general::network::SetFirewallOEMParam::
            PARAM_END_SOURCE_IP_ADDR:
        {
            std::variant<in_addr, in6_addr> ipAddr;
            std::array<uint8_t, sizeof(in_addr)> ipv4Bytes;
            std::array<uint8_t, sizeof(in6_addr)> ipv6Bytes;
            char tmp[128];
            bool isIPv4 = true;
            memset(tmp, 0, sizeof(tmp));
            try
            {
                if (req.size() - req.rawIndex == sizeof(in_addr))
                {
                    if (req.unpack(ipv4Bytes) != 0 || !req.fullyUnpacked())
                    {
                        return responseReqDataLenInvalid();
                    } // if
                    in_addr addr;
                    std::memcpy(&addr, ipv4Bytes.data(), ipv4Bytes.size());
                    if (!inet_ntop(AF_INET, &addr, tmp, sizeof(tmp)))
                    {
                        return responseInvalidFieldRequest();
                    } // if
                    isIPv4 = true;
                    ipAddr = std::move(addr);
                } // if
                else if (req.size() - req.rawIndex == sizeof(in6_addr))
                {
                    if (req.unpack(ipv6Bytes) != 0 || !req.fullyUnpacked())
                    {
                        return responseReqDataLenInvalid();
                    } // if
                    in6_addr addr;
                    std::memcpy(&addr, ipv6Bytes.data(), ipv6Bytes.size());
                    if (!inet_ntop(AF_INET6, &addr, tmp, sizeof(tmp)))
                    {
                        return responseInvalidFieldRequest();
                    } // if
                    isIPv4 = false;
                    ipAddr = std::move(addr);
                } // else if
                else
                {
                    req.trailingOk = true;
                    return responseReqDataLenInvalid();
                }
            }
            catch (const std::exception& e)
            {
                return ipmi::responseResponseError();
            }

            auto checkIPAddrOrder = [](int type, std::string addr1,
                                       std::string addr2) {
                if (type == AF_INET)
                {
                    in_addr compareAddr1, compareAddr2;
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        (std::string("Incorrect IP Range. Start IP Address: ") +
                         addr1 + "End IP Address: " + addr2 + "\n")
                            .c_str());
                    inet_pton(type, addr1.c_str(), &compareAddr1);
                    inet_pton(type, addr2.c_str(), &compareAddr2);
                    if (ntohl(compareAddr1.s_addr) > ntohl(compareAddr2.s_addr))
                    {
                        return -1;
                    } // if

                    return 0;
                } // if
                else if (type == AF_INET6)
                {
                    in6_addr compareAddr1, compareAddr2;
                    inet_pton(type, addr1.c_str(), &compareAddr1);
                    inet_pton(type, addr2.c_str(), &compareAddr2);
                    for (int i = 0; i < 4; i++)
                    {
                        if (ntohl(compareAddr1.s6_addr32[i]) >
                            ntohl(compareAddr2.s6_addr32[i]))
                        {
                            return 1;
                        } // else if
                    } // for

                    return 0;
                } // else if

                return -1;
            };

            if (static_cast<ami::general::network::SetFirewallOEMParam>(
                    parameter) == ami::general::network::SetFirewallOEMParam::
                                      PARAM_START_SOURCE_IP_ADDR)
            {
                if (!properties.endIPAddr.empty())
                {
                    if ((isIPv4 &&
                         properties.endIPAddr.find(":") != std::string::npos) ||
                        (!isIPv4 &&
                         properties.endIPAddr.find(":") == std::string::npos))
                    {
                        return responseInvalidFieldRequest();
                    } // if
                    else if (isIPv4 &&
                             checkIPAddrOrder(AF_INET, tmp,
                                              properties.endIPAddr) != 0)
                    {
                        return responseInvalidFieldRequest();
                    } // else if
                    else if (!isIPv4 &&
                             checkIPAddrOrder(AF_INET6, tmp,
                                              properties.endIPAddr) != 0)
                    {
                        return responseInvalidFieldRequest();
                    } // else if
                }
                properties.startIPAddr = tmp;
            }
            else
            {
                if (!properties.startIPAddr.empty())
                {
                    if ((isIPv4 && properties.startIPAddr.find(":") !=
                                       std::string::npos) ||
                        (!isIPv4 &&
                         properties.startIPAddr.find(":") == std::string::npos))
                    {
                        return responseInvalidFieldRequest();
                    } // if
                    else if (isIPv4 &&
                             checkIPAddrOrder(AF_INET, properties.startIPAddr,
                                              tmp) != 0)
                    {
                        return responseInvalidFieldRequest();
                    } // else if
                    else if (!isIPv4 &&
                             checkIPAddrOrder(AF_INET6, properties.startIPAddr,
                                              tmp) != 0)
                    {
                        return responseInvalidFieldRequest();
                    } // else if
                }
                properties.endIPAddr = tmp;
            }

            properties.control |=
                static_cast<uint8_t>(ami::general::network::FirewallFlags::IP);
            return ipmi::responseSuccess();
        }
        case ami::general::network::SetFirewallOEMParam::PARAM_START_PORT:
        case ami::general::network::SetFirewallOEMParam::PARAM_END_PORT:
        {
            uint16_t port;
            std::array<uint8_t, sizeof(uint16_t)> portBytes;
            if (req.unpack(portBytes) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            } // if

            std::memcpy(&port, portBytes.data(), portBytes.size());
            if (static_cast<ami::general::network::SetFirewallOEMParam>(
                    parameter) ==
                ami::general::network::SetFirewallOEMParam::PARAM_START_PORT)
            {
                if (properties.endPort != 0 && properties.endPort < ntohs(port))
                {
                    return responseReqDataLenInvalid();
                } // if
                properties.startPort = ntohs(port);
            }
            else
            {
                if (properties.startPort != 0 &&
                    properties.startPort > ntohs(port))
                {
                    return responseReqDataLenInvalid();
                } // if

                properties.endPort = ntohs(port);
            }
            properties.control |= static_cast<uint8_t>(
                ami::general::network::FirewallFlags::PORT);
            return ipmi::responseSuccess();
        }
        case ami::general::network::SetFirewallOEMParam::PARAM_SOURCE_MAC_ADDR:
        {
            std::array<uint8_t, sizeof(ether_addr)> macBytes;
            ether_addr mac;
            if (req.unpack(macBytes) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            } // if

            std::memcpy(&mac, macBytes.data(), macBytes.size());
            properties.macAddr = ether_ntoa(&mac);
            properties.control |=
                static_cast<uint8_t>(ami::general::network::FirewallFlags::MAC);
            return ipmi::responseSuccess();
        }
        case ami::general::network::SetFirewallOEMParam::PARAM_START_TIME:
        case ami::general::network::SetFirewallOEMParam::PARAM_END_TIME:
        {
            uint16_t year;
            uint8_t month, date, hour, min, sec;
            std::array<uint8_t, sizeof(uint16_t)> yearBytes;
            char tmp[128];
            memset(tmp, 0, sizeof(tmp));
            if (req.unpack(yearBytes, month, date, hour, min, sec) != 0 ||
                !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            } // if

            std::memcpy(&year, yearBytes.data(), yearBytes.size());
            memset(tmp, 0, sizeof(tmp));
            snprintf(tmp, sizeof(tmp), "%04d-%02d-%02dT%02d:%02d:%02d",
                     ntohs(year), month, date, hour, min, sec);
            if (dateTimeCheck(tmp))
                return responseInvalidFieldRequest();

            if (static_cast<ami::general::network::SetFirewallOEMParam>(
                    parameter) ==
                ami::general::network::SetFirewallOEMParam::PARAM_START_TIME)
            {
                if (!properties.endTime.empty() &&
                    dateTimeCompare(tmp, properties.endTime) != 0)
                {
                    return responseReqDataLenInvalid();
                }

                properties.startTime = tmp;
            }
            else
            {
                if (!properties.startTime.empty() &&
                    dateTimeCompare(properties.startTime, tmp) != 0)
                {
                    return responseReqDataLenInvalid();
                }

                properties.endTime = tmp;
            }
            properties.control |= static_cast<uint8_t>(
                ami::general::network::FirewallFlags::TIMEOUT);
            return ipmi::responseSuccess();
        }
        case ami::general::network::SetFirewallOEMParam::PARAM_APPLY:
        {
            int16_t retValue;
            uint8_t action;
            uint8_t IPver;
            if (req.unpack(action, IPver) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            } // if

            if ((properties.control &
                 static_cast<uint8_t>(
                     ami::general::network::FirewallFlags::PROTOCOL)) == 0)
            {
                try
                {
                    properties.protocol =
                        sdbusplus::xyz::openbmc_project::Network::server::
                            convertForMessage(FirewallIface::Protocol::ALL);
                    properties.control |= static_cast<uint8_t>(
                        ami::general::network::FirewallFlags::PROTOCOL);
                }
                catch (const std::exception& e)
                {
                    return ipmi::responseInvalidFieldRequest();
                }
            }

            if (IPver == 0b00)
            {
                properties.IPver = sdbusplus::xyz::openbmc_project::Network::
                    server::convertForMessage(FirewallIface::IP::IPV4);
            }
            else if (IPver == 0b01)
            {
                properties.IPver = sdbusplus::xyz::openbmc_project::Network::
                    server::convertForMessage(FirewallIface::IP::IPV6);
            }
            else if (IPver == 0b10)
            {
                properties.IPver = sdbusplus::xyz::openbmc_project::Network::
                    server::convertForMessage(FirewallIface::IP::BOTH);
            }
            else
            {
                properties = {};
                return ipmi::responseInvalidFieldRequest();
            }

            if (action == 0b01)
            {
                if ((!properties.startIPAddr.empty() &&
                     properties.startIPAddr.find(":") == std::string::npos &&
                     properties.IPver ==
                         sdbusplus::xyz::openbmc_project::Network::server::
                             convertForMessage(FirewallIface::IP::IPV6)) ||
                    (!properties.endIPAddr.empty() &&
                     properties.endIPAddr.find(":") == std::string::npos &&
                     properties.IPver ==
                         sdbusplus::xyz::openbmc_project::Network::server::
                             convertForMessage(FirewallIface::IP::IPV6)) ||
                    (!properties.startIPAddr.empty() &&
                     properties.startIPAddr.find(":") != std::string::npos &&
                     properties.IPver ==
                         sdbusplus::xyz::openbmc_project::Network::server::
                             convertForMessage(FirewallIface::IP::IPV4)) ||
                    (!properties.endIPAddr.empty() &&
                     properties.endIPAddr.find(":") != std::string::npos &&
                     properties.IPver ==
                         sdbusplus::xyz::openbmc_project::Network::server::
                             convertForMessage(FirewallIface::IP::IPV4)))
                {
                    return ipmi::responseInvalidFieldRequest();
                }

                auto method = dbus->new_method_call(
                    ami::general::network::phosphorNetworkService,
                    ami::general::network::firewallConfigurationObj,
                    ami::general::network::firewallConfigurationIntf,
                    "AddRule");
                method.append(properties.target, properties.control,
                              properties.protocol, properties.startIPAddr,
                              properties.endIPAddr, properties.startPort,
                              properties.endPort, properties.macAddr,
                              properties.startTime, properties.endTime,
                              properties.IPver);
                try
                {
                    auto reply = dbus->call(method);
                    reply.read(retValue);
                    properties = {};
                    if (retValue == 0)
                    {
                        return ipmi::responseSuccess();
                    }
                    else
                    {
                        return ipmi::responseResponseError();
                    }
                }
                catch (const sdbusplus::exception_t& e)
                {
                    properties = {};
                    return ipmi::responseResponseError();
                }
            } // if
            else if (action == 0x00)
            {
                if ((!properties.startIPAddr.empty() &&
                     properties.startIPAddr.find(":") == std::string::npos &&
                     properties.IPver ==
                         sdbusplus::xyz::openbmc_project::Network::server::
                             convertForMessage(FirewallIface::IP::IPV6)) ||
                    (!properties.endIPAddr.empty() &&
                     properties.endIPAddr.find(":") == std::string::npos &&
                     properties.IPver ==
                         sdbusplus::xyz::openbmc_project::Network::server::
                             convertForMessage(FirewallIface::IP::IPV6)) ||
                    (!properties.startIPAddr.empty() &&
                     properties.startIPAddr.find(":") != std::string::npos &&
                     properties.IPver ==
                         sdbusplus::xyz::openbmc_project::Network::server::
                             convertForMessage(FirewallIface::IP::IPV4)) ||
                    (!properties.endIPAddr.empty() &&
                     properties.endIPAddr.find(":") != std::string::npos &&
                     properties.IPver ==
                         sdbusplus::xyz::openbmc_project::Network::server::
                             convertForMessage(FirewallIface::IP::IPV4)))
                {
                    return ipmi::responseInvalidFieldRequest();
                }

                auto method = dbus->new_method_call(
                    ami::general::network::phosphorNetworkService,
                    ami::general::network::firewallConfigurationObj,
                    ami::general::network::firewallConfigurationIntf,
                    "DelRule");
                method.append(properties.target, properties.control,
                              properties.protocol, properties.startIPAddr,
                              properties.endIPAddr, properties.startPort,
                              properties.endPort, properties.macAddr,
                              properties.startTime, properties.endTime,
                              properties.IPver);
                try
                {
                    auto reply = dbus->call(method);
                    reply.read(retValue);
                    properties = {};
                    if (retValue == 0)
                        return ipmi::responseSuccess();
                    else
                        return ipmi::responseResponseError();
                }
                catch (const sdbusplus::exception_t& e)
                {
                    properties = {};
                    return ipmi::responseResponseError();
                }
            } // else if
            else
            {
                properties = {};
                return ipmi::responseInvalidFieldRequest();
            }

            return ipmi::responseSuccess();
        }
        case ami::general::network::SetFirewallOEMParam::PARAM_FLUSH:
        {
            uint8_t ipType;
            if (req.unpack(ipType) != 0 || !req.fullyUnpacked())
            {
                return responseInvalidFieldRequest();
            }

            auto request = dbus->new_method_call(
                ami::general::network::phosphorNetworkService,
                ami::general::network::firewallConfigurationObj,
                ami::general::network::firewallConfigurationIntf, "FlushAll");
            try
            {
                request.append(sdbusplus::xyz::openbmc_project::Network::
                                   server::convertForMessage(
                                       static_cast<FirewallIface::IP>(ipType)));
            }
            catch (const std::exception& e)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            dbus->call_noreply(request);
            return ipmi::responseSuccess();
        }
        default:
        {
            return ipmi::responseInvalidFieldRequest();
        }
    }

    return ipmi::responseUnspecifiedError();
}

ipmi::RspType<message::Payload> ipmiOEMGetFirewallConfiguration(
    uint8_t parameter, message::Payload& req)
{
    using FirewallIface =
        sdbusplus::xyz::openbmc_project::Network::server::FirewallConfiguration;
    using FirewallTuples =
        std::tuple<bool, std::string, uint8_t, std::string, std::string,
                   std::string, uint16_t, uint16_t, std::string, std::string,
                   std::string>;
    std::vector<FirewallTuples> tupleList;
    message::Payload payload;
    struct firewall_t
    {
        uint8_t target;
        uint8_t control;
        uint8_t protocol;
        uint16_t startPort;
        uint16_t stopPort;
        ether_addr macAddr;
        uint16_t startYear;
        uint8_t startMonth;
        uint8_t startDate;
        uint8_t startHour;
        uint8_t startMin;
        uint8_t startSec;
        uint16_t stopYear;
        uint8_t stopMonth;
        uint8_t stopDate;
        uint8_t stopHour;
        uint8_t stopMin;
        uint8_t stopSec;
    } ret;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();

    auto request = dbus->new_method_call(
        ami::general::network::phosphorNetworkService,
        ami::general::network::firewallConfigurationObj,
        ami::general::network::firewallConfigurationIntf, "GetRules");

    switch (static_cast<ami::general::network::GetFirewallOEMParam>(parameter))
    {
        case ami::general::network::GetFirewallOEMParam::PARAM_RULE_NUMBER:
        {
            uint8_t ipType;
            if (req.unpack(ipType) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            try
            {
                request.append(sdbusplus::xyz::openbmc_project::Network::
                                   server::convertForMessage(
                                       static_cast<FirewallIface::IP>(ipType)));
                auto resp = dbus->call(request);
                resp.read(tupleList);
                uint8_t num = 0;
                for (auto it = tupleList.begin(); it != tupleList.end(); it++)
                {
                    if (!(std::get<0>(*it)))
                    {
                        num++;
                    } // if
                } // for

                payload.pack(num);
            }
            catch (const std::exception& e1)
            {
                return responseInvalidFieldRequest();
            }

            return ipmi::responseSuccess(payload);
        }
        case ami::general::network::GetFirewallOEMParam::PARAM_IPV4_RULE:
        case ami::general::network::GetFirewallOEMParam::PARAM_IPV6_RULE:
        {
            uint8_t index;
            if (req.unpack(index) != 0 || !req.fullyUnpacked())
            {
                return responseReqDataLenInvalid();
            }

            try
            {
                if (static_cast<ami::general::network::GetFirewallOEMParam>(
                        parameter) ==
                    ami::general::network::GetFirewallOEMParam::PARAM_IPV4_RULE)
                {
                    request.append(
                        sdbusplus::xyz::openbmc_project::Network::server::
                            convertForMessage(FirewallIface::IP::IPV4));
                } // if
                else
                    request.append(
                        sdbusplus::xyz::openbmc_project::Network::server::
                            convertForMessage(FirewallIface::IP::IPV6));
            }
            catch (const std::exception& e)
            {
                return responseInvalidFieldRequest();
            }
            auto resp = dbus->call(request);
            resp.read(tupleList);
            if (tupleList.size() == 0)
            {
                return ipmi::responseParmOutOfRange();
            } // if
            else if (tupleList.size() <= index)
            {
                return ipmi::responseParmOutOfRange();
            }
            int i = 0;
            for (auto it = tupleList.begin(); it != tupleList.end(); it++)
            {
                if (std::get<0>(*it))
                {
                    i++;
                } // if
            } // for

            auto [preload, target, control, protocol, startIPAddr, endIPAddr,
                  startPort, endPort, macAddr, startTime,
                  endTime] = tupleList.at(i + index);
            memset(&ret, 0, sizeof(firewall_t));
            try
            {
                ret.target = static_cast<uint8_t>(
                    FirewallIface::convertTargetFromString(target));
                ret.protocol = static_cast<uint8_t>(
                    FirewallIface::convertProtocolFromString(protocol));
            }
            catch (const std::exception& e3)
            {
                return ipmi::responseInvalidFieldRequest();
            }

            ret.control = control;
            ret.startPort = ntohs(startPort);
            ret.stopPort = ntohs(endPort);
            if (!macAddr.empty())
            {
                ret.macAddr = *(ether_aton(macAddr.c_str()));
            } // if

            int tmps[6];
            if (!startTime.empty())
            {
                memset(tmps, 0, sizeof(tmps));
                sscanf(startTime.c_str(), "%d-%d-%dT%d:%d:%d", &tmps[0],
                       &tmps[1], &tmps[2], &tmps[3], &tmps[4], &tmps[5]);
                ret.startYear = ntohs(tmps[0]);
                ret.startMonth = tmps[1];
                ret.startDate = tmps[2];
                ret.startHour = tmps[3];
                ret.startMin = tmps[4];
                ret.startSec = tmps[5];
            } // if

            if (!endTime.empty())
            {
                memset(tmps, 0, sizeof(tmps));
                sscanf(endTime.c_str(), "%d-%d-%dT%d:%d:%d", &tmps[0], &tmps[1],
                       &tmps[2], &tmps[3], &tmps[4], &tmps[5]);
                ret.stopYear = ntohs(tmps[0]);
                ret.stopMonth = tmps[1];
                ret.stopDate = tmps[2];
                ret.stopHour = tmps[3];
                ret.stopMin = tmps[4];
                ret.stopSec = tmps[5];
            } // if

            payload.pack(ret.target, ret.control, ret.protocol, ret.startPort,
                         ret.stopPort);
            payload.pack(
                std::string_view{reinterpret_cast<const char*>(&ret.macAddr),
                                 sizeof(ether_addr)});
            payload.pack(ret.startYear, ret.startMonth, ret.startDate,
                         ret.startHour, ret.startMin);
            payload.pack(ret.startSec, ret.stopYear, ret.stopMonth,
                         ret.stopDate, ret.stopHour, ret.stopMin, ret.stopSec);

            if (static_cast<ami::general::network::GetFirewallOEMParam>(
                    parameter) ==
                ami::general::network::GetFirewallOEMParam::PARAM_IPV4_RULE)
            {
                std::string_view sv = startIPAddr;
                in_addr startAddr, stopAddr;
                memset(&startAddr, 0, sizeof(startAddr));
                memset(&stopAddr, 0, sizeof(stopAddr));
                if (sv.find_first_of("/") != std::string::npos)
                    sv.remove_suffix(
                        std::min(sv.size() - sv.find_first_of("/"), sv.size()));
                inet_pton(AF_INET, std::string(sv).c_str(), &startAddr);
                if (!endIPAddr.empty())
                    inet_pton(AF_INET, endIPAddr.c_str(), &stopAddr);
                payload.pack(
                    std::string_view{reinterpret_cast<const char*>(&startAddr),
                                     sizeof(in_addr)});
                payload.pack(std::string_view{
                    reinterpret_cast<const char*>(&stopAddr), sizeof(in_addr)});
            } // if
            else
            {
                std::string_view sv = startIPAddr;
                in6_addr startAddr, stopAddr;
                memset(&startAddr, 0, sizeof(startAddr));
                memset(&stopAddr, 0, sizeof(stopAddr));
                if (sv.find_first_of("/") != std::string::npos)
                    sv.remove_suffix(
                        std::min(sv.size() - sv.find_first_of("/"), sv.size()));
                inet_pton(AF_INET6, std::string(sv).c_str(), &startAddr);
                if (!endIPAddr.empty())
                    inet_pton(AF_INET6, endIPAddr.c_str(), &stopAddr);
                payload.pack(
                    std::string_view{reinterpret_cast<const char*>(&startAddr),
                                     sizeof(in6_addr)});
                payload.pack(
                    std::string_view{reinterpret_cast<const char*>(&stopAddr),
                                     sizeof(in6_addr)});
            } // else

            return ipmi::responseSuccess(payload);
        }
        default:
        {
            return ipmi::responseInvalidFieldRequest();
        }
    }

    return ipmi::responseUnspecifiedError();
}

ipmi::RspType<> ipmiOEMSetSELPolicy([[maybe_unused]] ipmi::Context::ptr ctx,
                                    uint8_t req)
{
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    std::string policy = [](uint8_t policy) {
        switch (policy)
        {
            case 0:
                return "xyz.openbmc_project.Logging.Settings.Policy.Linear";
            case 1:
                return "xyz.openbmc_project.Logging.Settings.Policy.Circular";
        }
        return ""; // For invalid request return emtpy string
    }(req);
    if (policy.empty())
    {
        return ipmi::responseInvalidFieldRequest();
    }

    try
    {
        auto service =
            ipmi::getService(*busp, loggingSettingIntf, loggingSettingObjPath);
        ipmi::setDbusProperty(*busp, service, loggingSettingObjPath,
                              loggingSettingIntf, "SelPolicy", policy.c_str());
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set SEL Policy",
            phosphor::logging::entry("MSG: %s", e.description()));
        return ipmi::response(ipmi::ccUnspecifiedError);
    }
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiOEMGetSELPolicy(
    [[maybe_unused]] ipmi::Context::ptr ctx)
{
    uint8_t policy;
    std::string policyStr;
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();

    try
    {
        auto service =
            ipmi::getService(*busp, loggingSettingIntf, loggingSettingObjPath);
        Value variant =
            ipmi::getDbusProperty(*busp, service, loggingSettingObjPath,
                                  loggingSettingIntf, "SelPolicy");
        policyStr = std::get<std::string>(variant);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get SEL Policy information",
            phosphor::logging::entry("MSG: %s", e.description()));
        return ipmi::response(ipmi::ccUnspecifiedError);
    }

    if (![&policy](std::string selPolicy) {
            if (selPolicy ==
                "xyz.openbmc_project.Logging.Settings.Policy.Linear")
            {
                policy = 0;
                return true;
            }
            else if (selPolicy ==
                     "xyz.openbmc_project.Logging.Settings.Policy.Circular")
            {
                policy = 1;
                return true;
            }
            else
                return false;
        }(policyStr))
    {
        return ipmi::responseResponseError();
    }
    return ipmi::responseSuccess(policy);
}

uint32_t CalculateCRC32(unsigned char* Buffer, uint32_t Size)
{
    uint32_t i, crc32 = 0xFFFFFFFF;

    /* Read the data and calculate crc32 */
    for (i = 0; i < Size; i++)
        crc32 = ((crc32) >> 8) ^
                CrcLookUpTable[(Buffer[i]) ^ ((crc32) & 0x000000FF)];
    return ~crc32;
}

ipmi::RspType<std::vector<uint8_t>> ipmiOEMReadCertficate(
    [[maybe_unused]] ipmi::Context::ptr ctx, uint8_t parameter,
    std::optional<uint8_t> MSBFileOffset, std::optional<uint8_t> FileOffset2,
    std::optional<uint8_t> FileOffset1, std::optional<uint8_t> LSBFileOffset,
    std::optional<uint8_t> MSBNumberOfBytesToRead,
    std::optional<uint8_t> NumberOfBytesToRead2,
    std::optional<uint8_t> NumberOfBytesToRead1,
    std::optional<uint8_t> LSBNumberOfBytesToRead)
{
    uint32_t offset = 0, nbytes = 0, crc32 = 0;
    std::vector<uint8_t> respBuf;

    std::string ca;
    std::vector<uint8_t> caVec;
    std::string caSubString;
    std::vector<uint8_t> caSubVec;
    std::vector<std::string> paths;

    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();

    if (parameter == readCRC32AndSize)
    {
        if (MSBFileOffset || FileOffset2 || FileOffset1 || LSBFileOffset ||
            MSBNumberOfBytesToRead || NumberOfBytesToRead2 ||
            NumberOfBytesToRead1 || LSBNumberOfBytesToRead)
        {
            return ipmi::responseReqDataLenInvalid();
        }
    }

    else if (parameter == readCACertFile)
    {
        if (!MSBFileOffset || !FileOffset2 || !FileOffset1 || !LSBFileOffset ||
            !MSBNumberOfBytesToRead || !NumberOfBytesToRead2 ||
            !NumberOfBytesToRead1 || !LSBNumberOfBytesToRead)
        {
            return ipmi::responseReqDataLenInvalid();
        }

        offset = (*MSBFileOffset << 24 | *FileOffset2 << 16 |
                  *FileOffset1 << 8 | *LSBFileOffset);

        nbytes = (*MSBNumberOfBytesToRead << 24 | *NumberOfBytesToRead2 << 16 |
                  *NumberOfBytesToRead1 << 8 | *LSBNumberOfBytesToRead);

        if (nbytes == 0)
        {
            return ipmi::response(
                ipmi::ipmiCCFileSelectorOrOffsetAndLengthOutOfRange);
        }
        if (nbytes > ipmbMaxDataSize)
        {
            return ipmi::response(
                ipmi::ipmiCCFileSelectorOrOffsetAndLengthOutOfRange);
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unsupported parameter");
        return ipmi::response(ccParameterNotSupported);
    }

    auto method = busp->new_method_call(
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");
    method.append("/xyz/openbmc_project/certs/authority/truststore/");
    method.append(0);
    method.append(
        std::array<const char*, 1>{"xyz.openbmc_project.Certs.Certificate"});
    try
    {
        sdbusplus::message_t reply = busp->call(method);
        reply.read(paths);

        if (paths.size() < 1)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to cert messages");
            return ipmi::response(ipmi::ipmiCCNoCertGenerated);
        }
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get Truststore genereated certificate",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::response(ipmi::ipmiCCNoCertGenerated);
    }

    try
    {
        Value variant = ipmi::getDbusProperty(
            *busp, "xyz.openbmc_project.Certs.Manager.Authority.Truststore",
            paths[0].c_str(), "xyz.openbmc_project.Certs.Certificate",
            "CertificateString");
        ca = std::get<std::string>(variant);
        caVec.assign(ca.begin(), ca.end());
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get Truststore genereated certificate",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::response(ipmi::ipmiCCNoCertGenerated);
    }

    if ((off_t)(offset + nbytes) > ca.size())
    {
        return ipmi::response(
            ipmi::ipmiCCFileSelectorOrOffsetAndLengthOutOfRange);
    }

    caSubString = ca.substr(offset, nbytes);
    caSubVec.assign(caSubString.begin(), caSubString.end());

    if (parameter == readCRC32AndSize)
    {
        crc32 = CalculateCRC32(static_cast<unsigned char*>(caVec.data()),
                               static_cast<uint32_t>(caVec.size()));

        respBuf.push_back(
            (crc32 &
             0xff)); // Byte 1 (LSB) of the 32-bit value of the cert file crc32
        respBuf.push_back(
            ((crc32 >> 8) &
             0xff)); // Byte 2 of the 32-bit value of the cert file crc32
        respBuf.push_back(
            ((crc32 >> 16) &
             0xff)); // Byte 3 of the 32-bit value of the cert file crc32
        respBuf.push_back(
            ((crc32 >> 24) &
             0xff)); // Byte 1 (MSB) of the 32-bit value of the cert file crc32
        // fileSize
        respBuf.push_back(
            (caVec.size() &
             0xff)); // Byte 1 (LSB) of the 32-bit value of the cert file size
        respBuf.push_back(
            ((caVec.size() >> 8) &
             0xff)); // Byte 2 of the 32-bit value of the cert file size
        respBuf.push_back(
            ((caVec.size() >> 16) &
             0xff)); // Byte 3 of the 32-bit value of the cert file size
        respBuf.push_back(
            ((caVec.size() >> 24) &
             0xff)); // Byte 1 (MSB) of the 32-bit value of the cert file size

        return ipmi::responseSuccess(respBuf);
    }

    return ipmi::responseSuccess(caSubVec);
}

ipmi::RspType<uint8_t> ipmiOEMGetKCSStatus(
    [[maybe_unused]] ipmi::Context::ptr ctx)
{
    try
    {
        // Establish a D-Bus connection
        auto dbus = getSdBus();

        // Create method call message to get the service unit properties
        auto method = dbus->new_method_call(systemDService, systemDObjPath,
                                            systemDMgrIntf, "GetUnit");
        method.append(ipmiKcsService);

        auto reply = dbus->call(method);

        // Process the reply to extract the service status
        std::variant<std::string> currentState;
        sdbusplus::message::object_path unitTargetPath;

        reply.read(unitTargetPath);

        method = dbus->new_method_call(
            systemDService,
            static_cast<const std::string&>(unitTargetPath).c_str(),
            systemDInterfaceUnit, "Get");

        method.append("org.freedesktop.systemd1.Unit", "ActiveState");
        try
        {
            auto result = dbus->call(method);
            result.read(currentState);
        }
        catch (const sdbusplus::exception_t& e)
        {
            syslog(LOG_WARNING, "Error in ActiveState Get:%s\n", e.what());
            return ipmi::responseResponseError();
        }
        // Check the service state
        const auto& currentStateStr = std::get<std::string>(currentState);

        uint8_t kcsstate = 0;

        if (currentStateStr == activeState ||
            currentStateStr == activatingState)
        {
            kcsstate = 1;
        }
        else
        {
            kcsstate = 0;
        }

        return ipmi::responseSuccess(kcsstate);
    }
    catch (const sdbusplus::exception_t& e)
    {
        return ipmi::responseSuccess(static_cast<uint8_t>(KCSStatus::Disable));
    }
}

ipmi::RspType<> ipmiOEMSetKCSStatus(ipmi::Context::ptr ctx, uint8_t reqData)
{
    constexpr bool runtimeOnly = false;
    constexpr bool force = false;

    if (reqData == static_cast<uint8_t>(KCSStatus::Disable))
    {
        auto dbus = getSdBus();
        auto method = dbus->new_method_call(systemDService, systemDObjPath,
                                            systemDMgrIntf, "StopUnit");
        method.append(ipmiKcsService, "replace");
        auto reply = dbus->call(method);

        // Append additional method call for disabling the unit
        boost::system::error_code ec;
        ctx->bus->yield_method_call(
            ctx->yield, ec, systemDService, systemDObjPath, systemDMgrIntf,
            "DisableUnitFiles",
            std::array<const char*, 1>{ipmiKcsService.c_str()}, runtimeOnly);
        return ipmi::responseSuccess();
    }
    else if (reqData == static_cast<uint8_t>(KCSStatus::Enable))
    {
        boost::system::error_code ec;
        ctx->bus->yield_method_call(
            ctx->yield, ec, systemDService, systemDObjPath, systemDMgrIntf,
            "EnableUnitFiles",
            std::array<const char*, 1>{ipmiKcsService.c_str()}, runtimeOnly,
            force);

        auto dbus = getSdBus();
        auto method = dbus->new_method_call(systemDService, systemDObjPath,
                                            systemDMgrIntf, "StartUnit");
        method.append(ipmiKcsService, "replace");
        auto reply = dbus->call(method);
        return ipmi::responseSuccess();
    }

    else
    {
        return ipmi::responseResponseError();
    }
}

ipmi::RspType<> ipmiOEMCancelTask([[maybe_unused]] ipmi::Context::ptr ctx,
                                  uint8_t req)
{
    if (req == INVALID_ID)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    ipmi::ObjectTree objectTree;

    boost::system::error_code ec =
        ipmi::getAllDbusObjects(ctx, systemRoot, taskIntf, objectTree);

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to fetch Task object from dbus",
            phosphor::logging::entry("INTERFACE=%s", taskIntf),
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        return ipmi::responseUnspecifiedError();
    }

    for (auto& softObject : objectTree)
    {
        const std::string& objPath = softObject.first;
        const std::string& serviceName = softObject.second.begin()->first;
        ipmi::PropertyMap result;

        ec = ipmi::getAllDbusProperties(ctx, serviceName, objPath, taskIntf,
                                        result);
        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to fetch Task properties",
                phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
            return ipmi::responseUnspecifiedError();
        }

        const uint16_t* id = nullptr;
        std::string status;

        for (const auto& [propName, propVariant] : result)
        {
            if (propName == "TaskId")
            {
                id = std::get_if<uint16_t>(&propVariant);
            }
            else if (propName == "Status")
            {
                status = std::get<std::string>(propVariant);
            }
        }

        if (*id == req && (status.compare(newTask) == 0))
        {
            try
            {
                ipmi::setDbusProperty(ctx, serviceName, objPath, taskIntf,
                                      "Status", cancelTask);
                return ipmi::response(ipmi::ccSuccess);
            }
            catch (const sdbusplus::exception_t& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMCancelTask: can't set Task Status!",
                    phosphor::logging::entry("EXCEPTION=%s", e.what()));
                return ipmi::responseResponseError();
            }
        }
    }

    // couldn't find requested ID
    return ipmi::responseInvalidFieldRequest();
}

ipmi::RspType<uint8_t, uint8_t> ipmiGetUsbDescription(uint8_t type)
{
    uint8_t msbId;
    uint8_t lsbId;
    if (type == 0x01)
    {
        // Get the USB Vendor Id
        msbId = (uint8_t)((USB_VENDOR_ID >> 8) & 0xff);
        lsbId = (uint8_t)(USB_VENDOR_ID & 0xff);
        return ipmi::responseSuccess(msbId, lsbId);
    }
    else if (type == 0x02)
    {
        // Get the USB Product Id
        msbId = (uint8_t)((USB_PRODUCT_ID >> 8) & 0xff);
        lsbId = (uint8_t)(USB_PRODUCT_ID & 0xff);
        return ipmi::responseSuccess(msbId, lsbId);
    }
    else
    {
        return ipmi::responseInvalidFieldRequest();
    }
}
ipmi::RspType<std::vector<uint8_t>> ipmiGetUsbSerialNum()
{
    // Get the USB Serial Number
    std::vector<uint8_t> usbSerialNum;
    usbSerialNum.push_back(USB_SERIAL_NUM);
    return ipmi::responseSuccess(usbSerialNum);
}

ipmi::RspType<std::vector<uint8_t>> ipmiGetRedfishHostName()
{
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        auto service =
            ipmi::getService(*dbus, networkConfigIntf, networkConfigObj);
        auto hostname = ipmi::getDbusProperty(*dbus, service, networkConfigObj,
                                              networkConfigIntf, "HostName");
        std::vector<uint8_t> respHostNameBuf;
        std::copy(std::get<std::string>(hostname).begin(),
                  std::get<std::string>(hostname).end(),
                  std::back_inserter(respHostNameBuf));
        return ipmi::responseSuccess(respHostNameBuf);
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to get HostName",
                        phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseResponseError();
    }
}

ipmi::RspType<uint8_t> ipmiGetipmiChannelRfHi()
{
    std::ifstream jsonFile(channelConfigDefaultFilename);
    if (!jsonFile.good())
    {
        log<level::INFO>("JSON file not found",
                         entry("FILE_NAME=%s", channelConfigDefaultFilename));
        return ipmi::responseResponseError();
    }

    nlohmann::json data = nullptr;
    try
    {
        data = nlohmann::json::parse(jsonFile, nullptr, false);
    }
    catch (const nlohmann::json::parse_error& e)
    {
        log<level::DEBUG>("Corrupted channel config.",
                          entry("MSG=%s", e.what()));
        return ipmi::responseResponseError();
    }

    bool chFound = false;
    uint8_t chNum;
    for (chNum = 0; chNum < maxIpmiChannels; chNum++)
    {
        try
        {
            std::string chKey = std::to_string(chNum);
            nlohmann::json jsonChData = data[chKey].get<nlohmann::json>();
            if (jsonChData.is_null() ||
                (jsonChData[nameString].get<std::string>() !=
                 redfishHostInterfaceChannel))
            {
                log<level::WARNING>(
                    "Channel not configured for Redfish Host Interface",
                    entry("CHANNEL_NUM=%d", chNum));
                continue;
            }
            nlohmann::json jsonChInfo =
                jsonChData[channelInfoString].get<nlohmann::json>();
            if (jsonChInfo.is_null())
            {
                log<level::ERR>("Invalid/corrupted channel config file");
                return ipmi::responseResponseError();
            }

            if ((jsonChData[isValidString].get<bool>() == true) &&
                (jsonChInfo[mediumTypeString].get<std::string>() ==
                 "lan-802.3") &&
                (jsonChInfo[protocolTypeString].get<std::string>() ==
                 "ipmb-1.0") &&
                (jsonChInfo[sessionSupportedString].get<std::string>() ==
                 "multi-session") &&
                (jsonChInfo[isIpmiString].get<bool>() == true))
            {
                chFound = true;
                break;
            }
        }
        catch (const nlohmann::json::parse_error& e)
        {
            log<level::DEBUG>("Json Exception caught.",
                              entry("MSG=%s", e.what()));
            return ipmi::responseResponseError();
        }
    }
    jsonFile.close();
    if (chFound)
    {
        return ipmi::responseSuccess(chNum);
    }
    return ipmi::responseInvalidCommandOnLun();
}

bool getRfUuid(std::string& rfUuid)
{
    std::ifstream persistentDataFilePath(
        "/home/root/bmcweb_persistent_data.json");
    if (persistentDataFilePath.is_open())
    {
        auto data =
            nlohmann::json::parse(persistentDataFilePath, nullptr, false);
        if (data.is_discarded())
        {
            phosphor::logging::log<level::ERR>(
                "ipmiGetRedfishServiceUuid: Error parsing persistent data in "
                "json file.");
            return false;
        }
        else
        {
            for (const auto& item : data.items())
            {
                if (item.key() == "system_uuid")
                {
                    const std::string* jSystemUuid =
                        item.value().get_ptr<const std::string*>();
                    if (jSystemUuid != nullptr)
                    {
                        rfUuid = *jSystemUuid;
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

ipmi::RspType<std::vector<uint8_t>> ipmiGetRedfishServiceUuid()
{
    std::string rfUuid;
    bool ret = getRfUuid(rfUuid);
    if (!ret)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetRedfishServiceUuid: Error reading Redfish Service UUID "
            "File.");
        return ipmi::responseResponseError();
    }

    // As per Redfish Host Interface Spec v1.3.0
    // The Redfish UUID is 16byte and should be represented as below:
    // Ex: {00112233-4455-6677-8899-AABBCCDDEEFF}
    // 0x33 0x22 0x11 0x00 0x55 0x44 0x77 0x66 0x88 0x99 0xAA 0xBB 0xCC 0xDD
    // 0xEE 0xFF

    int start = 0;
    int noOfBytes = 5;
    int leftBytes = 3;
    unsigned int totalBytes = 16;
    std::string bytes;
    std::string::size_type found = 0;
    std::vector<uint8_t> resBuf;

    for (int index = 0; index < noOfBytes; index++)
    {
        found = rfUuid.find('-', found + 1);
        if (found == std::string::npos)
        {
            if (index != noOfBytes - 1)
            {
                break;
            }
        }

        if (index == noOfBytes - 1)
        {
            bytes = rfUuid.substr(start);
        }
        else
        {
            bytes = rfUuid.substr(start, found - start);
        }

        if (index < leftBytes)
        {
            std::reverse(bytes.begin(), bytes.end());
            for (unsigned int leftIndex = 0; leftIndex < bytes.length();
                 leftIndex += 2)
            {
                std::swap(bytes[leftIndex + 1], bytes[leftIndex]);
                resBuf.push_back(
                    std::stoi(bytes.substr(leftIndex, 2), nullptr, 16));
            }
        }
        else
        {
            for (unsigned int rightIndex = 0; rightIndex < bytes.length();
                 rightIndex += 2)
            {
                resBuf.push_back(
                    std::stoi(bytes.substr(rightIndex, 2), nullptr, 16));
            }
        }
        start = found + 1;
    }

    if (resBuf.size() != totalBytes)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetRedfishServiceUuid: Invalid Redfish Service UUID found.");
        return ipmi::responseResponseError();
    }
    return ipmi::responseSuccess(resBuf);
}

ipmi::RspType<uint8_t, uint8_t> ipmiGetRedfishServicePort()
{
    // default Redfish Service Port Number is 443
    int redfishPort = 443;
    uint8_t lsb = redfishPort & 0xff;
    uint8_t msb = redfishPort >> 8 & 0xff;
    return ipmi::responseSuccess(msb, lsb);
}

static bool getCredentialBootStrap()
{
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        auto biosService =
            ipmi::getService(*dbus, biosConfigMgrIface, biosConfigMgrPath);
        auto credentialBootStrap =
            ipmi::getDbusProperty(*dbus, biosService, biosConfigMgrPath,
                                  biosConfigMgrIface, "CredentialBootstrap");

        return std::get<bool>(credentialBootStrap);
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to get CredentialBootstrap status",
                        phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return false;
    }
}

static void setCredentialBootStrap(const uint8_t& disableCredBootStrap)
{
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    auto biosService =
        ipmi::getService(*dbus, biosConfigMgrIface, biosConfigMgrPath);
    // if disable crendential BootStrap status is 0xa5,
    // then Keep credential bootstrapping enabled
    if (disableCredBootStrap == 0xa5)
    {
        ipmi::setDbusProperty(*dbus, biosService, biosConfigMgrPath,
                              biosConfigMgrIface, "CredentialBootstrap",
                              bool(true));
        if constexpr (debug)
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "ipmiGetBootStrapAccount: Disable CredentialBootstrapping"
                "property set to true");
        }
    }
    else
    {
        ipmi::setDbusProperty(*dbus, biosService, biosConfigMgrPath,
                              biosConfigMgrIface, "CredentialBootstrap",
                              bool(false));
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "ipmiGetBootStrapAccount: Disable CredentialBootstrapping"
            "property set to false");
    }
}

static int pamFunctionConversation(int numMsg, const struct pam_message** msg,
                                   struct pam_response** resp, void* appdataPtr)
{
    if (appdataPtr == nullptr)
    {
        return PAM_CONV_ERR;
    }
    if (numMsg <= 0 || numMsg >= PAM_MAX_NUM_MSG)
    {
        return PAM_CONV_ERR;
    }

    for (int i = 0; i < numMsg; ++i)
    {
        /* Ignore all PAM messages except prompting for hidden input */
        if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF)
        {
            continue;
        }

        /* Assume PAM is only prompting for the password as hidden input */
        /* Allocate memory only when PAM_PROMPT_ECHO_OFF is encounterred */
        char* appPass = reinterpret_cast<char*>(appdataPtr);
        size_t appPassSize = std::strlen(appPass);
        if (appPassSize >= PAM_MAX_RESP_SIZE)
        {
            return PAM_CONV_ERR;
        }

        char* pass = reinterpret_cast<char*>(malloc(appPassSize + 1));
        if (pass == nullptr)
        {
            return PAM_BUF_ERR;
        }

        void* ptr =
            calloc(static_cast<size_t>(numMsg), sizeof(struct pam_response));
        if (ptr == nullptr)
        {
            free(pass);
            return PAM_BUF_ERR;
        }

        std::strncpy(pass, appPass, appPassSize + 1);
        *resp = reinterpret_cast<pam_response*>(ptr);
        resp[i]->resp = pass;
        return PAM_SUCCESS;
    }
    return PAM_CONV_ERR;
}

int pamUpdatePasswd(const char* username, const char* password)
{
    const struct pam_conv localConversation = {pamFunctionConversation,
                                               const_cast<char*>(password)};
    pam_handle_t* localAuthHandle = NULL; // this gets set by pam_start
    int retval =
        pam_start("passwd", username, &localConversation, &localAuthHandle);
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }

    retval = pam_chauthtok(localAuthHandle, PAM_SILENT);
    if (retval != PAM_SUCCESS)
    {
        pam_end(localAuthHandle, retval);
        return retval;
    }
    return pam_end(localAuthHandle, PAM_SUCCESS);
}

bool isValidUserName(ipmi::Context::ptr ctx, const std::string& userName)
{
    if (userName.empty())
    {
        phosphor::logging::log<level::ERR>("Requested empty UserName string");
        return false;
    }
    if (!std::regex_match(userName.c_str(),
                          std::regex("[a-zA-z_][a-zA-Z_0-9]*")))
    {
        phosphor::logging::log<level::ERR>("Unsupported characters in string");
        return false;
    }

    boost::system::error_code ec;
    GetSubTreePathsType subtreePaths =
        ctx->bus->yield_method_call<GetSubTreePathsType>(
            ctx->yield, ec, "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths",
            userMgrObjBasePath, 0, std::array<const char*, 1>{usersInterface});
    if (ec)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetBootStrapAccount: Failed to get User Paths");
        return false;
    }

    if (subtreePaths.empty())
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetBootStrapAccount: empty subtreepaths");
        return false;
    }

    for (const auto& objectPath : subtreePaths)
    {
        if (objectPath.find(userName) != std::string::npos)
        {
            log<level::ERR>(
                "User name already exists",
                phosphor::logging::entry("UserName= %s", userName.c_str()));
            return false;
        }
    }
    return true;
}

bool isPrintable(char ch)
{
    return std::isprint(static_cast<unsigned char>(ch)) != 0;
}

bool isUppercase(char ch)
{
    return std::isupper(static_cast<unsigned char>(ch)) != 0;
}

bool isLowercase(char ch)
{
    return std::islower(static_cast<unsigned char>(ch)) != 0;
}

bool isDigit(char ch)
{
    return std::isdigit(static_cast<unsigned char>(ch)) != 0;
}

bool isSpecialChar(char ch)
{
    return isPrintable(ch) && !std::isalnum(static_cast<unsigned char>(ch));
}

char getRandomChar(std::ifstream& randFp)
{
    char byte;
    while (true)
    {
        if (randFp.get(byte) && isPrintable(byte))
        {
            return byte;
        }
    }
}

std::string generateRandomPassword()
{
    std::ifstream randFp("/dev/urandom", std::ifstream::binary);
    std::string password;

    if (!randFp.is_open())
    {
        std::cerr << "Failed to open urandom file" << std::endl;
        return "";
    }

    srand(time(nullptr)); // Seed for rand function

    // Add one uppercase letter
    password.push_back(getRandomChar(randFp));
    while (!isUppercase(password[0]))
    {
        password[0] = getRandomChar(randFp);
    }

    // Add one lowercase letter
    password.push_back(getRandomChar(randFp));
    while (!isLowercase(password[1]))
    {
        password[1] = getRandomChar(randFp);
    }

    // Add one digit
    password.push_back(getRandomChar(randFp));
    while (!isDigit(password[2]))
    {
        password[2] = getRandomChar(randFp);
    }

    // Add one special character
    password.push_back(getRandomChar(randFp));
    while (!isSpecialChar(password[3]))
    {
        password[3] = getRandomChar(randFp);
    }

    // Fill the remaining 12 characters
    for (size_t i = 4; i < 16; ++i)
    {
        password.push_back(getRandomChar(randFp));
    }

    randFp.close();
    std::random_shuffle(password.begin(), password.end()); // Shuffle characters

    return password;
}

bool getAlphaNumString(std::string& uniqueStr)
{
    std::ifstream randFp("/dev/urandom", std::ifstream::in);
    char byte;
    uint8_t maxStrSize = 16;

    if (!randFp.is_open())
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetBootStrapAccount: Failed to open urandom file");
        return false;
    }

    for (uint8_t it = 0; it < maxStrSize; it++)
    {
        while (1)
        {
            if (randFp.get(byte))
            {
                if (iswalnum(byte))
                {
                    break;
                }
            }
        }
        uniqueStr.push_back(byte);
    }
    randFp.close();
    return true;
}

ipmi::RspType<std::vector<uint8_t>, std::vector<uint8_t>>
    ipmiGetBootStrapAccount(ipmi::Context::ptr ctx,
                            uint8_t disableCredBootStrap)
{
    try
    {
        // Check the CredentialBootstrapping property status
        bool isCredentialBootStrapSet = getCredentialBootStrap();
        if (!isCredentialBootStrapSet)
        {
            phosphor::logging::log<level::ERR>(
                "ipmiGetBootStrapAccount: Credential BootStrapping Disabled "
                "Get BootStrap Account command rejected.");
            return ipmi::response(ipmi::ipmiCCBootStrappingDisabled);
        }

        struct group* gr = getgrent();
        int num_of_accounts = 0;
        while (gr != nullptr)
        {
            if (strcmp(gr->gr_name, "redfish-hostiface") == 0)
            {
                while (gr->gr_mem[num_of_accounts] != nullptr)
                {
                    num_of_accounts++;
                }
                break;
            }
            gr = getgrent();
        }
        endgrent();

        if (num_of_accounts >= 5)
        {
            phosphor::logging::log<level::ERR>(
                "ipmiGetBootStrapAccount: Max HI user limit is reached");
            return ipmi::responseResponseError();
        }

        std::string userName;
        std::string password;

        bool ret = getAlphaNumString(userName);
        if (!ret || !isValidUserName(ctx, userName))
        {
            phosphor::logging::log<level::ERR>(
                "ipmiGetBootStrapAccount: Failed to generate valid UserName");
            return ipmi::responseResponseError();
        }

        password = generateRandomPassword();
        if (password.empty())
        {
            phosphor::logging::log<level::ERR>(
                "ipmiGetBootStrapAccount: Failed to generate alphanumeric "
                "Password");
            return ipmi::responseResponseError();
        }
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();

        std::string service =
            getService(*dbus, userMgrInterface, userMgrObjBasePath);

        // create the new user with only redfish-hostiface group access
        auto method = dbus->new_method_call(service.c_str(), userMgrObjBasePath,
                                            userMgrInterface, createUserMethod);
        method.append(userName, std::vector<std::string>{"redfish-hostiface"},
                      "priv-admin", true);
        auto reply = dbus->call(method);
        if (reply.is_method_error())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error returns from call to dbus. BootStrap Failed");
            return ipmi::responseResponseError();
        }
        // update the password
        boost::system::error_code ec;
        int retval = pamUpdatePasswd(userName.c_str(), password.c_str());
        if (retval != PAM_SUCCESS)
        {
            dbus->yield_method_call<void>(ctx->yield, ec, service.c_str(),
                                          userMgrObjBasePath + userName,
                                          usersDeleteIface, "Delete");
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiGetBootStrapAccount : Failed to update password.");
            return ipmi::responseUnspecifiedError();
        }
        else
        {
            // update the "CredentialBootstrap" Dbus property w.r.to
            // disable crendential BootStrap status
            setCredentialBootStrap(disableCredBootStrap);
            std::vector<uint8_t> respUserNameBuf, respPasswordBuf;
            std::copy(userName.begin(), userName.end(),
                      std::back_inserter(respUserNameBuf));
            std::copy(password.begin(), password.end(),
                      std::back_inserter(respPasswordBuf));
            return ipmi::responseSuccess(respUserNameBuf, respPasswordBuf);
        }
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiGetBootStrapAccount : Failed to generate BootStrap Account "
            "Credentials");
        return ipmi::responseResponseError();
    }
}

ipmi::RspType<> ipmiOEMSetSNMPStatus([[maybe_unused]] ipmi::Context::ptr ctx,
                                     bool reqData, uint7_t reserved)
{
    if (reserved != 0)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    try
    {
        ipmi::setDbusProperty(ctx, snmpService, snmpObjPath, snmpUtilsIntf,
                              "SnmpTrapStatus", static_cast<bool>(reqData));
        return ipmi::responseSuccess();
    }
    catch (const sdbusplus::exception_t& e)
    {
        return ipmi::responseResponseError();
    }
}

ipmi::RspType<bool, uint7_t> ipmiOEMGetSNMPStatus(ipmi::Context::ptr ctx)
{
    bool status = 0;
    try
    {
        ipmi::getDbusProperty(ctx, snmpService, snmpObjPath, snmpUtilsIntf,
                              "SnmpTrapStatus", status);
    }
    catch (const sdbusplus::exception_t& e)
    {
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(status, 0);
}

ipmi::RspType<std::vector<uint8_t>> ipmiGetManagerCertFingerPrint(
    uint8_t certNum)
{
    unsigned int n;
    const EVP_MD* fdig = EVP_sha256();
    // Check the CredentialBootstrapping property status,
    // if disabled, then reject the command with success code.
    bool isCredentialBootStrapSet = getCredentialBootStrap();
    if (!isCredentialBootStrapSet)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetManagerCertFingerPrint: Credential BootStrapping Disabled "
            "Get Manager Certificate FingerPrint command rejected.");
        return ipmi::response(ipmi::ipmiCCBootStrappingDisabled);
    }

    if (certNum != 1)
    {
        phosphor::logging::log<level::ERR>(
            "ipmiGetManagerCertFingerPrint: Invalid certificate number "
            "Get Manager Certificate failed");
        return ipmi::response(ipmi::ipmiCCCertificateNumberInvalid);
    }
    BIO* cert;
    X509* x = NULL;
    cert = BIO_new_file(defaultCertPath.c_str(), "rb");
    if (cert == NULL)
    {
        log<level::ERR>(
            "ipmiGetManagerCertFingerPrint: unable to open certificate");
        return ipmi::response(ipmi::ccResponseError);
    }
    x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
    if (x == NULL)
    {
        BIO_free(cert);
        log<level::ERR>(
            "ipmiGetManagerCertFingerPrint: unable to load certificate");
        return ipmi::response(ipmi::ccResponseError);
    }
    std::vector<uint8_t> fingerPrintData(EVP_MAX_MD_SIZE);
    if (!X509_digest(x, fdig, fingerPrintData.data(), &n))
    {
        X509_free(x);
        BIO_free(cert);
        log<level::ERR>("ipmiGetManagerCertFingerPrint: out of memory");
        return ipmi::response(ipmi::ccResponseError);
    }
    fingerPrintData.resize(n);

    X509_free(x);
    BIO_free(cert);

    try
    {
        std::vector<uint8_t> respBuf;
        respBuf.push_back(1); // 01h: SHA-256. The length of the fingerprint
                              // will be 32 bytes.

        for (const auto& data : fingerPrintData)
        {
            respBuf.push_back(data);
        }
        return ipmi::responseSuccess(respBuf);
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to get Manager Cert FingerPrint",
                        phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseResponseError();
    }
}

ipmi::RspType<> ipmiOEMEnDisPwrSaveMode(std::optional<uint8_t> req)
{
    int resp;
    if (!req)
    {
        return ipmi::responseReqDataLenInvalid();
    }

    if ((*req) != 0 && (*req) != 1)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();

    auto method = dbus->new_method_call(settingsService, settingsObjPath,
                                        settingsUSBIntf, "SetUSBPowerSaveMode");

    method.append(static_cast<int>(*req));
    try
    {
        auto data = dbus->call(method);
        data.read(resp);
        if (resp == 0xC0 || resp < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMEnDisPwrSaveMode: Error - Busy node or ioctl failed");
            return ipmi::response(ipmi::ccBusy);
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        std::cerr << "SetUSBPowerSaveMode method call failed \n";
        return ipmi::response(ipmi::ccUnspecifiedError);
    }
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiOEMGetPwrSaveMode()
{
    int resp;

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();

    auto method = dbus->new_method_call(settingsService, settingsObjPath,
                                        settingsUSBIntf, "GetUSBPowerSaveMode");

    try
    {
        auto data = dbus->call(method);
        data.read(resp);
        if (resp == 0)
        {
            std::cerr << "virtual hub usb device connected to HOST \n";
        }
        else if (resp == 1)
        {
            std::cerr << "virtual hub usb device disconnected from HOST \n";
        }
        else if (resp == 0xC0 || resp < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMGetPwrSaveMode: Error - Busy node or ioctl failed");
            return ipmi::response(ipmi::ccBusy);
        }
    }
    catch (sdbusplus::exception_t& e)
    {
        std::cerr << "GetUSBPowerSaveMode method call failed \n";
        return ipmi::response(ipmi::ccUnspecifiedError);
    }
    return ipmi::responseSuccess(resp);
}

/*
 * getHostStatus
 * helper function for Get Host Status
 */
bool getHostStatus()
{
    bool HostStatus = false;
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    try
    {
        constexpr const char* HostStatePath =
            "/xyz/openbmc_project/state/host0";
        constexpr const char* HostStateIntf = "xyz.openbmc_project.State.Host";
        auto service = ipmi::getService(*busp, HostStateIntf, HostStatePath);

        ipmi::Value variant = ipmi::getDbusProperty(
            *busp, service, HostStatePath, HostStateIntf, "CurrentHostState");
        std::string HostState = std::get<std::string>(variant);
        if (HostState == CurrentHostState)
        {
            HostStatus = true;
        }
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to fetch power state property",
                        entry("ERROR=%s", e.what()));
        return false;
    }
    return HostStatus;
}

/*Trigger Screenshot*/
ipmi::RspType<> ipmiOEMTriggerScreenshot()
{
    if (getHostStatus())
    {
        try
        {
            int32_t scrnshot = 1;
            std::string resp;
            sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

            std::string service = ipmi::getService(bus, TriggerScreenShotIntf,
                                                   TriggerScreenShotObjPath);

            auto methodCall =
                bus.new_method_call(service.c_str(), TriggerScreenShotObjPath,
                                    TriggerScreenShotIntf, "TriggerScreenshot");
            methodCall.append(scrnshot);
            auto reply = bus.call(methodCall);
            reply.read(resp);

            if (resp == "Success")
            {
                return ipmi::responseSuccess();
            }
            else if (resp == "Failure")
            {
                return ipmi::responseUnspecifiedError();
            }
        }
        catch (const sdbusplus::exception_t& e)
        {
            log<level::ERR>("Failed to Set Trigger the Screenshot",
                            phosphor::logging::entry("EXCEPTION=%s", e.what()));
            return ipmi::responseUnspecifiedError();
        }
    }
    else
    {
        return ipmi::responseCommandNotAvailable();
    }

    return ipmi::responseSuccess();
}

/** @brief implementes Setting KVM Session Timeout
 *  @param[in] sessionTimeout - KVM Session Timeout
 *  @returns ipmi completion code.
 */
ipmi::RspType<uint8_t> ipmiOEMSetSessionTimeout(uint32_t sessionTimeout)
{
    uint64_t value = static_cast<uint64_t>(sessionTimeout);
    if (value < minSessionTimeOut || value > maxSessionTimeOut)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();

    try
    {
        ipmi::setDbusProperty(*busp, serviceManagerService,
                              serviceMgrKvmObjPath, serviceConfigInterface,
                              "SessionTimeOut", value);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set SessionTimeOut value",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

/** @brief implementes to Get KVM Session Timeout
 *  @returns IPMI completion code with following data
 *   - KVM Session Timeout in Seconds.(four bytes)
 */
ipmi::RspType<uint32_t> ipmiOEMGetSessionTimeout()
{
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    uint64_t sessionTimeOut = 0;
    try
    {
        auto value = ipmi::getDbusProperty(
            *dbus, serviceManagerService, serviceMgrKvmObjPath,
            serviceConfigInterface, "SessionTimeOut");

        sessionTimeOut = std::get<uint64_t>(value);
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to get SessionTimeOut value",
                        phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess(static_cast<uint32_t>(sessionTimeOut));
}

// control BMC services
std::string getBmcServiceConfigMgrName()
{
    static std::string serviceCfgMgr{};
    if (serviceCfgMgr.empty())
    {
        try
        {
            auto sdbusp = getSdBus();
            serviceCfgMgr = ipmi::getService(*sdbusp, objectManagerIntf,
                                             serviceConfigBasePath);
        }
        catch (const sdbusplus::exception_t& e)
        {
            serviceCfgMgr.clear();
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error: In fetching disabling service manager name");
            return serviceCfgMgr;
        }
    }
    return serviceCfgMgr;
}

static inline void checkAndThrowError(boost::system::error_code& ec,
                                      const std::string& msg)
{
    if (ec)
    {
        std::string msgToLog = ec.message() + (msg.empty() ? "" : " - " + msg);
        phosphor::logging::log<phosphor::logging::level::ERR>(msgToLog.c_str());
        throw sdbusplus::exception::SdBusError(-EIO, msgToLog.c_str());
    }
    return;
}

// General function to get a property value
template <typename T>
static inline T getPropertyValue(const DbusInterfaceMap& intfMap,
                                 const std::string& intfName,
                                 const std::string& propName)
{
    for (const auto& intf : intfMap)
    {
        if (intf.first == intfName)
        {
            auto it = intf.second.find(propName);
            if (it == intf.second.end())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error: in getting property value");
                throw sdbusplus::exception::SdBusError(
                    -EIO, "ERROR in reading property value");
            }
            T value = std::get<T>(it->second);
            return value;
        }
    }
    return T{};
}

// Function to get the value of the Masked property
static inline bool getEnabledValue(const DbusInterfaceMap& intfMap)
{
    bool maskedValue =
        getPropertyValue<bool>(intfMap, serviceConfigAttrIntf, propMasked);
    bool result = !maskedValue;
    return result;
}

// Function to get the value of the Port property
static inline uint16_t getPortValue(const DbusInterfaceMap& intfMap)
{
    return getPropertyValue<uint16_t>(intfMap, socketConfigAttrIntf, propPort);
}

// Helper function to get the object map
ObjectValueTree getObjectMap(boost::asio::yield_context& yield)
{
    auto sdbusp = getSdBus();
    boost::system::error_code ec;
    auto objectMap = sdbusp->yield_method_call<ObjectValueTree>(
        yield, ec, getBmcServiceConfigMgrName().c_str(), serviceConfigBasePath,
        objectManagerIntf, getMgdObjMethod);
    checkAndThrowError(ec, "GetMangagedObjects for service cfg failed");
    return objectMap;
}

// Function to get BMC control services
ipmi::RspType<uint16_t> ipmiOEMGetBmcControlServices(
    boost::asio::yield_context yield, uint16_t serviceValue = 0)
{
    uint16_t resultValue = 0;

    if (serviceValue > maxServiceBit)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    try
    {
        auto objectMap = getObjectMap(yield);

        for (const auto& services : bmcService)
        {
            if (serviceValue != 0)
            {
                const uint16_t serviceMask = 1 << services.first;
                if (!(serviceValue & serviceMask))
                {
                    continue;
                }
            }

            for (const auto& obj : objectMap)
            {
                if (boost::algorithm::starts_with(obj.first.filename(),
                                                  services.second))
                {
                    resultValue |= getEnabledValue(obj.second)
                                   << services.first;
                    break;
                }
            }
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(resultValue);
}

// Function to get specified BMC service port number
ipmi::RspType<uint16_t> ipmiOEMGetBmcServicePortValue(
    boost::asio::yield_context yield, uint16_t serviceValue)
{
    uint16_t portValue = 0;

    if ((serviceValue > maxServiceBit) ||
        (serviceValue & (serviceValue - 1)) != 0)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    try
    {
        auto objectMap = getObjectMap(yield);
        for (const auto& services : bmcService)
        {
            const uint16_t serviceMask = 1 << services.first;

            if (!(serviceValue & serviceMask))
            {
                continue;
            }

            for (const auto& obj : objectMap)
            {
                if (boost::algorithm::starts_with(obj.first.filename(),
                                                  services.second))
                {
                    portValue = getPortValue(obj.second);
                    break;
                }
            }
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess(portValue);
}

ipmi::RspType<uint8_t> ipmiOEMSetBmcControlServices(
    boost::asio::yield_context yield, uint8_t state, uint16_t serviceValue)
{
    constexpr uint16_t servicesRsvdMask = 0x8000;
    constexpr uint8_t enableService = 0x1;

    if ((state > enableService) || (serviceValue & servicesRsvdMask) ||
        !serviceValue || (serviceValue > maxServiceBit))
    {
        return ipmi::responseInvalidFieldRequest();
    }
    try
    {
        auto objectMap = getObjectMap(yield);
        for (const auto& services : bmcService)
        {
            // services.first holds the bit position of the service, check
            // whether it has to be updated.
            const uint16_t serviceMask = 1 << services.first;

            if (!(serviceValue & serviceMask))
            {
                continue;
            }
            for (const auto& obj : objectMap)
            {
                if (boost::algorithm::starts_with(obj.first.filename(),
                                                  services.second))
                {
                    if (state != getEnabledValue(obj.second))
                    {
                        auto sdbusp = getSdBus();
                        boost::system::error_code ec;
                        sdbusp->yield_method_call<>(
                            yield, ec, getBmcServiceConfigMgrName().c_str(),
                            obj.first.str, dBusPropIntf, "Set",
                            serviceConfigAttrIntf, propMasked,
                            ipmi::DbusVariant(!state));
                        checkAndThrowError(ec, "Set Masked property failed");
                    }
                }
            }
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess();
}

/** @brief implementes To Clear KVM Session Information
 *  @returns ipmi completion code.
 */
ipmi::RspType<uint8_t> ipmiOEMClearSessionInfo()
{
    bool resp;

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();

    auto method =
        dbus->new_method_call(sessionManagerService, sessionManagerObjPath,
                              sessionManagerIntf, "Clear");

    try
    {
        auto data = dbus->call(method);
        data.read(resp);
        if (resp == false)
        {
            return ipmi::response(ipmi::ccUnspecifiedError);
        }
    }
    catch (sdbusplus::exception_t& e)
    {
        log<level::ERR>("Failed to Clear Session Information",
                        phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::response(ipmi::ccUnspecifiedError);
    }
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiOEMSetBmcServicePortValue(
    boost::asio::yield_context yield, uint16_t serviceValue, uint16_t portValue)
{
    if ((portValue > maxPortValue) || (portValue == 0) ||
        (serviceValue > maxServiceBit) ||
        ((serviceValue & (serviceValue - 1)) != 0))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    try
    {
        auto objectMap = getObjectMap(yield);
        for (const auto& services : bmcService)
        {
            const uint16_t serviceMask = 1 << services.first;
            if (!(serviceValue & serviceMask))
            {
                continue;
            }

            bool portPropertyFound = false;
            for (const auto& obj : objectMap)
            {
                if (boost::algorithm::starts_with(obj.first.filename(),
                                                  services.second))
                {
                    auto it = obj.second.find(socketConfigAttrIntf);
                    if (it != obj.second.end() &&
                        it->second.find(propPort) != it->second.end())
                    {
                        auto sdbusp = getSdBus();
                        boost::system::error_code ec;
                        sdbusp->yield_method_call<>(
                            yield, ec, getBmcServiceConfigMgrName().c_str(),
                            obj.first.str, dBusPropIntf, "Set",
                            socketConfigAttrIntf, propPort,
                            ipmi::DbusVariant(portValue));
                        checkAndThrowError(ec, "Set Port property failed");
                        portPropertyFound = true;
                        break;
                    }
                }
            }
            if (!portPropertyFound)
            {
                std::cout << "Port property not defined for service: "
                          << services.second << std::endl;
                return ipmi::responseInvalidFieldRequest();
            }
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

/** @brief Get the latest boot cycle's POST Code, if there is one.
 ** @param[in] ctx   - ipmi Context point
 ** @return   Boot Cycle indes, Post Code length, POST Code vector
 **/
ipmi::RspType<uint16_t, uint16_t, std::vector<uint8_t>> ipmiGetBiosPostCode()
{
    using namespace ipmi::ami::general;
    uint64_t pcode = 0;
    uint16_t bootIndex = 1; // 1 for the latest boot cycle's POST Code
    uint16_t postVecLen = 0;
    uint16_t postVecStart = 0;
    uint16_t postRetLen = 0;
    using postcode_t = std::tuple<uint64_t, std::vector<uint8_t>>;
    postcode_t postCodeTup(0, {0});
    std::vector<postcode_t> postCodeVector = {};
    std::vector<uint8_t> postCodeVectorRet = {};

    // to get the oldest POST Code
    // getBIOSbootCycCount(bootIndex);

    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        // if chassis in power off state, return error code
        auto powerState =
            ipmi::getDbusProperty(*dbus, chassisStateService, chassisStatePath,
                                  chassisStateIntf, "CurrentPowerState");
        if (std::get<std::string>(powerState) ==
            "xyz.openbmc_project.State.Chassis.PowerState.Off")
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Host is in power off state");
            return ipmi::response(ipmiCCBIOSPostCodeError);
        }

        std::string service =
            getService(*dbus, postCodesIntf, postCodesObjPath);
        // call POST Code Service method
        auto method = dbus->new_method_call(postCodesService, postCodesObjPath,
                                            postCodesIntf, "GetPostCodes");
        method.append(bootIndex);
        auto postCodesMsgRet = dbus->call(method);
        if (postCodesMsgRet.is_method_error())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error returns from call to dbus.");
            return ipmi::response(ipmiCCBIOSPostCodeError);
        }

        postCodesMsgRet.read(postCodeVector);
        if (postCodeVector.empty())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "No post code is found from call to dbus.");
            return ipmi::response(ipmiCCBIOSPostCodeError);
        }

        postVecLen = postCodeVector.size();

        if (postVecLen <= cmdGetBiosPostCodeToIpmiMaxSize)
            postVecStart = 0;
        else
        {
            // adjust the start position so the end-portion of post code is sent
            postVecStart = postVecLen - cmdGetBiosPostCodeToIpmiMaxSize;
        }

        for (int i = postVecStart; i < postVecLen; i++)
        {
            postCodeTup = postCodeVector[i];
            pcode = std::get<0>(postCodeTup);
            postCodeVectorRet.push_back(pcode);
            // sd_journal_print(LOG_ERR, "0x%02llx ", pcode);
        }

        postRetLen = postCodeVectorRet.size();
        return ipmi::responseSuccess(bootIndex, postRetLen, postCodeVectorRet);
    }
    catch (const std::exception& e)
    {
        return ipmi::response(ipmiCCBIOSPostCodeError);
    }

    return ipmi::response(ipmiCCBIOSPostCodeError);
}

ipmi::RspType<std::vector<uint8_t>> ipmiOEMGetTimezone(
    [[maybe_unused]] ipmi::Context::ptr ctx)
{
    std::string timezone;

    auto conn = sdbusplus::bus::new_default();
    auto method = conn.new_method_call(
        "org.freedesktop.timedate1",       // service name
        "/org/freedesktop/timedate1",      // object path
        "org.freedesktop.DBus.Properties", // interface name
        "Get"                              // method name
    );

    method.append("org.freedesktop.timedate1", "Timezone");

    try
    {
        auto reply = conn.call(method);
        // Extract the value from the response
        std::variant<std::string> value;
        reply.read(value);
        timezone = std::get<std::string>(value);
    }
    catch (const std::exception& e)
    {
        return ipmi::responseResponseError();
    }

    std::vector<uint8_t> response(timezone.begin(), timezone.end());

    // Return the timezone bytes directly
    return ipmi::responseSuccess(response);
}
ipmi::RspType<> ipmiOEMSetTimezone([[maybe_unused]] ipmi::Context::ptr ctx,
                                   const std::vector<uint8_t>& reqData)
{
    // Convert the input data to a string
    std::string newTimezone(reqData.begin(), reqData.end());

    // Check if the timezone length is valid
    if (newTimezone.length() == 0 || newTimezone.length() > maxlentimezone)
    {
        return ipmi::responseParmOutOfRange();
    }

    if (newTimezone.length() == 0 || newTimezone.length() < maxlentimezone)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    try
    {
        auto conn = sdbusplus::bus::new_default();
        auto method = conn.new_method_call(
            "org.freedesktop.timedate1",  // service name
            "/org/freedesktop/timedate1", // object path
            "org.freedesktop.timedate1",  // interface name
            "SetTimezone"                 // method name
        );

        // Append the interface, property name, and new timezone value
        method.append(newTimezone, false);

        auto reply = conn.call(method);
    }
    catch (const sdbusplus::exception_t& e)
    {
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiOEMSetExtlogConfigs(
    bool EnableLog, uint7_t reserved, uint8_t LogLevel, uint8_t ReqResLogLevel)
{
    if (reserved != 0 || LogLevel > 1 || ReqResLogLevel > 2)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        auto service =
            ipmi::getService(*dbus, extlogconfigIntf, extlogconfigObjPath);
        ipmi::setDbusProperty(*dbus, service, extlogconfigObjPath,
                              extlogconfigIntf, "EnableExtlog", EnableLog);
        ipmi::setDbusProperty(*dbus, service, extlogconfigObjPath,
                              extlogconfigIntf, "LogLevel", LogLevel);
        ipmi::setDbusProperty(*dbus, service, extlogconfigObjPath,
                              extlogconfigIntf, "ReqResLogLevel",
                              ReqResLogLevel);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set Extlog config",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<bool, uint7_t, uint8_t, uint8_t> ipmiOEMGetExtlogConfigs()
{
    bool ExtlogStatus = false;
    uint8_t LogLevel = 0;
    uint8_t ReqResLogLevel = 0;

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        auto service =
            ipmi::getService(*dbus, extlogconfigIntf, extlogconfigObjPath);

        ipmi::PropertyMap result = ipmi::getAllDbusProperties(
            *dbus, service, extlogconfigObjPath, extlogconfigIntf);
        ExtlogStatus = std::get<bool>(result.at("EnableExtlog"));
        LogLevel = std::get<uint8_t>(result.at("LogLevel"));
        ReqResLogLevel = std::get<uint8_t>(result.at("ReqResLogLevel"));
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get Extlog config",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(ExtlogStatus, 0, LogLevel, ReqResLogLevel);
}

static void registerOEMFunctions(void)
{
    if constexpr (debug)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Registering OEM commands");
    }
    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetBmcVersionString, Privilege::User,
                    ipmiOEMGetBmcVersionString);

    ipmiPrintAndRegister(intel::netFnGeneral,
                         intel::general::cmdGetChassisIdentifier, NULL,
                         ipmiOEMGetChassisIdentifier,
                         PRIVILEGE_USER); // get chassis identifier

    ipmiPrintAndRegister(intel::netFnGeneral, intel::general::cmdSetSystemGUID,
                         NULL, ipmiOEMSetSystemGUID,
                         PRIVILEGE_ADMIN); // set system guid

    // <Disable BMC System Reset Action>
    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdDisableBMCSystemReset, Privilege::Admin,
                    ipmiOEMDisableBMCSystemReset);

    // <Get BMC Reset Disables>
    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetBMCResetDisables, Privilege::Admin,
                    ipmiOEMGetBMCResetDisables);

    ipmiPrintAndRegister(intel::netFnGeneral, intel::general::cmdSetBIOSID,
                         NULL, ipmiOEMSetBIOSID, PRIVILEGE_ADMIN);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetOEMDeviceInfo, Privilege::User,
                    ipmiOEMGetDeviceInfo);

    ipmiPrintAndRegister(intel::netFnGeneral,
                         intel::general::cmdGetAICSlotFRUIDSlotPosRecords, NULL,
                         ipmiOEMGetAICFRU, PRIVILEGE_USER);

    registerHandler(prioOpenBmcBase, intel::netFnGeneral,
                    intel::general::cmdSendEmbeddedFWUpdStatus,
                    Privilege::Operator, ipmiOEMSendEmbeddedFwUpdStatus);

    registerHandler(prioOpenBmcBase, intel::netFnApp, intel::app::cmdSlotIpmb,
                    Privilege::Admin, ipmiOEMSlotIpmb);

    ipmiPrintAndRegister(intel::netFnGeneral,
                         intel::general::cmdSetPowerRestoreDelay, NULL,
                         ipmiOEMSetPowerRestoreDelay, PRIVILEGE_OPERATOR);

    ipmiPrintAndRegister(intel::netFnGeneral,
                         intel::general::cmdGetPowerRestoreDelay, NULL,
                         ipmiOEMGetPowerRestoreDelay, PRIVILEGE_USER);

    registerHandler(prioOpenBmcBase, intel::netFnGeneral,
                    intel::general::cmdSetOEMUser2Activation,
                    Privilege::Callback, ipmiOEMSetUser2Activation);

    registerHandler(prioOpenBmcBase, intel::netFnGeneral,
                    intel::general::cmdSetSpecialUserPassword,
                    Privilege::Callback, ipmiOEMSetSpecialUserPassword);

    registerHandler(prioOpenBmcBase, intel::netFnPlatform,
                    intel::general::cmdReadCertficate, Privilege::Callback,
                    ipmiOEMReadCertficate);

    // <Get Processor Error Config>
    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetProcessorErrConfig, Privilege::User,
                    ipmiOEMGetProcessorErrConfig);

    // <Set Processor Error Config>
    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetProcessorErrConfig, Privilege::Admin,
                    ipmiOEMSetProcessorErrConfig);

    ipmiPrintAndRegister(intel::netFnGeneral,
                         intel::general::cmdSetShutdownPolicy, NULL,
                         ipmiOEMSetShutdownPolicy, PRIVILEGE_ADMIN);

    ipmiPrintAndRegister(intel::netFnGeneral,
                         intel::general::cmdGetShutdownPolicy, NULL,
                         ipmiOEMGetShutdownPolicy, PRIVILEGE_ADMIN);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetFanConfig, Privilege::User,
                    ipmiOEMSetFanConfig);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetFanConfig, Privilege::User,
                    ipmiOEMGetFanConfig);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetFanSpeedOffset, Privilege::User,
                    ipmiOEMGetFanSpeedOffset);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetFanSpeedOffset, Privilege::User,
                    ipmiOEMSetFanSpeedOffset);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetFscParameter, Privilege::User,
                    ipmiOEMSetFscParameter);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetFscParameter, Privilege::User,
                    ipmiOEMGetFscParameter);

    registerHandler(prioOpenBmcBase, intel::netFnGeneral,
                    intel::general::cmdReadBaseBoardProductId, Privilege::Admin,
                    ipmiOEMReadBoardProductId);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetNmiStatus, Privilege::User,
                    ipmiOEMGetNmiSource);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetNmiStatus, Privilege::Operator,
                    ipmiOEMSetNmiSource);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetEfiBootOptions, Privilege::User,
                    ipmiOemGetEfiBootOptions);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetEfiBootOptions, Privilege::Operator,
                    ipmiOemSetEfiBootOptions);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetSecurityMode, Privilege::User,
                    ipmiGetSecurityMode);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetSecurityMode, Privilege::Admin,
                    ipmiSetSecurityMode);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetLEDStatus, Privilege::Admin,
                    ipmiOEMGetLEDStatus);

    ipmiPrintAndRegister(ipmi::intel::netFnPlatform,
                         ipmi::intel::platform::cmdCfgHostSerialPortSpeed, NULL,
                         ipmiOEMCfgHostSerialPortSpeed, PRIVILEGE_ADMIN);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetFaultIndication, Privilege::Operator,
                    ipmiOEMSetFaultIndication);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetColdRedundancyConfig, Privilege::User,
                    ipmiOEMSetCRConfig);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetColdRedundancyConfig, Privilege::User,
                    ipmiOEMGetCRConfig);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdRestoreConfiguration, Privilege::Admin,
                    ipmiRestoreConfiguration);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetDimmOffset, Privilege::Operator,
                    ipmiOEMSetDimmOffset);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetDimmOffset, Privilege::Operator,
                    ipmiOEMGetDimmOffset);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetPSUVersion, Privilege::User,
                    ipmiOEMGetPSUVersion);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetBufferSize, Privilege::User,
                    ipmiOEMGetBufferSize);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdOEMGetReading, Privilege::User,
                    ipmiOEMGetReading);

    registerHandler(prioOemBase, intel::netFnApp, intel::app::cmdPFRMailboxRead,
                    Privilege::Admin, ipmiOEMReadPFRMailbox);

    // <Set Firewall Configuration>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMSetFirewallConfiguration,
                    Privilege::Admin, ipmiOEMSetFirewallConfiguration);

    // // <Get Firewall Configuration>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMGetFirewallConfiguration,
                    Privilege::User, ipmiOEMGetFirewallConfiguration);

    // <Set SMTP Config>
    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdOEMSetSmtpConfig, Privilege::Admin,
                    ipmiOEMSetSmtpConfig);

    // <Get SMTP Config>
    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdOEMGetSmtpConfig, Privilege::User,
                    ipmiOEMGetSmtpConfig);

    // <Set SEL Policy>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMSetSELPolicy, Privilege::Admin,
                    ipmiOEMSetSELPolicy);

    // <Get SEL Policy>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMGetSELPolicy, Privilege::User,
                    ipmiOEMGetSELPolicy);

    //<Get KCS Status>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMGetKCSStatus, Privilege::User,
                    ipmiOEMGetKCSStatus);

    //<Set KCS Status>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMSetKCSStatus, Privilege::Admin,
                    ipmiOEMSetKCSStatus);

    // <Cancel Task>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMCancelTask, Privilege::Admin,
                    ipmiOEMCancelTask);

    //<Set SNMP trap Status>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMSetSNMPStatus, Privilege::Admin,
                    ipmiOEMSetSNMPStatus);

    // <Get SNMP trap Status>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMGetSNMPstatus, Privilege::User,
                    ipmiOEMGetSNMPStatus);

    // GetBiosPostCodes
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdGetBiosPostCode, Privilege::User,
                    ipmiGetBiosPostCode);
    //<Get Timezone>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMGetTimezone, Privilege::User,
                    ipmiOEMGetTimezone);
    //<Set Timezone>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMSetTimezone, Privilege::User,
                    ipmiOEMSetTimezone);

    // <Get USB Description>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::intel::netFnOem),
        entry("Cmd:[%02Xh]", ipmi::intel::misc::cmdGetUsbDescription));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnOem,
                          ipmi::intel::misc::cmdGetUsbDescription,
                          ipmi::Privilege::Admin, ipmi::ipmiGetUsbDescription);

    // <Get Virtual USB Serial Number>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::intel::netFnOem),
        entry("Cmd:[%02Xh]", ipmi::intel::misc::cmdGetUsbSerialNum));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnOem,
                          ipmi::intel::misc::cmdGetUsbSerialNum,
                          ipmi::Privilege::Admin, ipmi::ipmiGetUsbSerialNum);

    // <Get Redfish Service Hostname>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::intel::netFnOem),
        entry("Cmd:[%02Xh]", ipmi::intel::misc::cmdGetRedfishHostName));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnOem,
                          ipmi::intel::misc::cmdGetRedfishHostName,
                          ipmi::Privilege::Admin, ipmi::ipmiGetRedfishHostName);

    // <Get IPMI Channel Number of Redfish HostInterface>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::intel::netFnOem),
        entry("Cmd:[%02Xh]", ipmi::intel::misc::cmdGetipmiChannelRfHi));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnOem,
                          ipmi::intel::misc::cmdGetipmiChannelRfHi,
                          ipmi::Privilege::Admin, ipmi::ipmiGetipmiChannelRfHi);

    // <Get Redfish Service UUID>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::intel::netFnOem),
        entry("Cmd:[%02Xh]", ipmi::intel::misc::cmdGetRedfishServiceUuid));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnOem,
                          ipmi::intel::misc::cmdGetRedfishServiceUuid,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetRedfishServiceUuid);

    // <Get Redfish Service Port Number>
    log<level::NOTICE>(
        "Registering ", entry("NetFn:[%02Xh], ", ipmi::intel::netFnOem),
        entry("Cmd:[%02Xh]", ipmi::intel::misc::cmdGetRedfishServicePort));

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnOem,
                          ipmi::intel::misc::cmdGetRedfishServicePort,
                          ipmi::Privilege::Admin,
                          ipmi::ipmiGetRedfishServicePort);

    // <Get Bootstrap Account Credentials>
    log<level::NOTICE>(
        "Registering ", entry("GrpExt:[%02Xh], ", ipmi::intel::netGroupExt),
        entry("Cmd:[%02Xh]", ipmi::intel::misc::cmdGetBootStrapAcc));

    ipmi::registerGroupHandler(
        ipmi::prioOpenBmcBase, ipmi::intel::netGroupExt,
        ipmi::intel::misc::cmdGetBootStrapAcc, ipmi::Privilege::sysIface,
        ipmi::ipmiGetBootStrapAccount);

    // <Get Manager Certificate Fingerprint>
    log<level::NOTICE>(
        "Registering ", entry("GrpExt:[%02Xh], ", ipmi::intel::netGroupExt),
        entry("Cmd:[%02Xh]", ipmi::intel::misc::cmdGetManagerCertFingerPrint));

    ipmi::registerGroupHandler(
        ipmi::prioOpenBmcBase, ipmi::intel::netGroupExt,
        ipmi::intel::misc::cmdGetManagerCertFingerPrint, ipmi::Privilege::Admin,
        ipmi::ipmiGetManagerCertFingerPrint);

    // <Enable Disable Power Save Mode>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMEnDisPowerSaveMode, Privilege::Admin,
                    ipmiOEMEnDisPwrSaveMode);

    // <Get Power Save Mode>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMGetPowerSaveMode, Privilege::Admin,
                    ipmiOEMGetPwrSaveMode);

    //<TriggerScreenshot>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMTriggerScreenshot, Privilege::Admin,
                    ipmiOEMTriggerScreenshot);

    // <Set KVM Session Timeout>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMSetSessionTimeout, Privilege::Admin,
                    ipmiOEMSetSessionTimeout);

    // <Get KVM Session Timeout>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMGetSessionTimeout, Privilege::Admin,
                    ipmiOEMGetSessionTimeout);
    // control BMC services
    //  <Set Bmc Service Status>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdSetBmcServiceStatus, Privilege::Admin,
                    ipmiOEMSetBmcControlServices);

    // <Get Bmc Service Status>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdGetBmcServiceStatus, Privilege::User,
                    ipmiOEMGetBmcControlServices);

    // <Set Bmc Service Port Value>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdSetBmcServicePortValue, Privilege::Admin,
                    ipmiOEMSetBmcServicePortValue);

    // <Get Bmc Service Port Value>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdGetBmcServicePortValue, Privilege::User,
                    ipmiOEMGetBmcServicePortValue);

    // <Clear Session Information>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMClearSessionInfo, Privilege::Admin,
                    ipmiOEMClearSessionInfo);

    // <Set Extlog Configurations>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMSetExtlogConfigs, Privilege::Admin,
                    ipmiOEMSetExtlogConfigs);

    // <Get Extlog Configurations>
    registerHandler(prioOemBase, ami::netFnGeneral,
                    ami::general::cmdOEMGetExtlogConfigs, Privilege::User,
                    ipmiOEMGetExtlogConfigs);
}

} // namespace ipmi

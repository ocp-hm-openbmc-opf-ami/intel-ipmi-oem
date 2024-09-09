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

#include <bridgingcommands.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <manufacturingcommands.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message.hpp>
#include <storagecommands.hpp>
#include <user_channel/channel_layer.hpp>

#include <bitset>
#include <cstring>
#include <map>
#include <variant>
#include <vector>

static constexpr const char* wdtService = "xyz.openbmc_project.Watchdog";
static constexpr const char* wdtInterface =
    "xyz.openbmc_project.State.Watchdog";
static constexpr const char* wdtObjPath = "/xyz/openbmc_project/watchdog/host0";
static constexpr const char* wdtInterruptFlagProp =
    "PreTimeoutInterruptOccurFlag";

static constexpr const char* ipmbBus = "xyz.openbmc_project.Ipmi.Channel.Ipmb";
static constexpr const char* ipmbObj = "/xyz/openbmc_project/Ipmi/Channel/Ipmb";
static constexpr const char* ipmbIntf = "org.openbmc.Ipmb";

static constexpr const char* loggingService = "xyz.openbmc_project.Logging";

/*D-bus details for BMC Global enable */
static constexpr const char* settingService = "xyz.openbmc_project.Settings";
static constexpr const char* globalEnblObjpath =
    "/xyz/openbmc_project/control/globalenables";
static constexpr const char* globalEnblInterface =
    "xyz.openbmc_project.Control.BMC.Globalenables";

constexpr std::string eventDirstr = "EVENT_DIR";
constexpr std::string generateIdstr = "GENERATOR_ID";
constexpr std::string sensorEventData = "SENSOR_DATA";
constexpr std::string sensorTypestr = "SENSOR_TYPE";
std::string recordTypestr = "RECORD_TYPE";

static Bridging bridging;
static bool eventMessageBufferFlag = false;

void Bridging::clearResponseQueue()
{
    responseQueue.clear();
}

/**
 * @brief utils for checksum
 */
static bool ipmbChecksumValidate(const uint8_t* data, uint8_t length)
{
    if (data == nullptr)
    {
        return false;
    }

    uint8_t checksum = 0;

    for (uint8_t idx = 0; idx < length; idx++)
    {
        checksum += data[idx];
    }

    if (0 == checksum)
    {
        return true;
    }

    return false;
}

static uint8_t ipmbChecksumCompute(uint8_t* data, uint8_t length)
{
    if (data == nullptr)
    {
        return 0;
    }

    uint8_t checksum = 0;

    for (uint8_t idx = 0; idx < length; idx++)
    {
        checksum += data[idx];
    }

    checksum = (~checksum) + 1;
    return checksum;
}

static inline bool
    ipmbConnectionHeaderChecksumValidate(const ipmbHeader* ipmbHeader)
{
    return ipmbChecksumValidate(reinterpret_cast<const uint8_t*>(ipmbHeader),
                                ipmbConnectionHeaderLength);
}

static inline bool
    ipmbDataChecksumValidate(const ipmbHeader* ipmbHeader, size_t length)
{
    return ipmbChecksumValidate((reinterpret_cast<const uint8_t*>(ipmbHeader) +
                                 ipmbConnectionHeaderLength),
                                (length - ipmbConnectionHeaderLength));
}

static bool isFrameValid(const ipmbHeader* frame, size_t length)
{
    if ((length < ipmbMinFrameLength) || (length > ipmbMaxFrameLength))
    {
        return false;
    }

    if (false == ipmbConnectionHeaderChecksumValidate(frame))
    {
        return false;
    }

    if (false == ipmbDataChecksumValidate(frame, length))
    {
        return false;
    }

    return true;
}

IpmbRequest::IpmbRequest(const ipmbHeader* ipmbBuffer, size_t bufferLength)
{
    address = ipmbBuffer->Header.Req.address;
    netFn = ipmbNetFnGet(ipmbBuffer->Header.Req.rsNetFnLUN);
    rsLun = ipmbLunFromNetFnLunGet(ipmbBuffer->Header.Req.rsNetFnLUN);
    rqSA = ipmbBuffer->Header.Req.rqSA;
    seq = ipmbSeqGet(ipmbBuffer->Header.Req.rqSeqLUN);
    rqLun = ipmbLunFromSeqLunGet(ipmbBuffer->Header.Req.rqSeqLUN);
    cmd = ipmbBuffer->Header.Req.cmd;

    size_t dataLength =
        bufferLength - (ipmbConnectionHeaderLength +
                        ipmbRequestDataHeaderLength + ipmbChecksumSize);

    if (dataLength > 0)
    {
        data.insert(data.end(), ipmbBuffer->Header.Req.data,
                    &ipmbBuffer->Header.Req.data[dataLength]);
    }
}

IpmbResponse::IpmbResponse(uint8_t address, uint8_t netFn, uint8_t rqLun,
                           uint8_t rsSA, uint8_t seq, uint8_t rsLun,
                           uint8_t cmd, uint8_t completionCode,
                           std::vector<uint8_t>& inputData) :
    address(address), netFn(netFn), rqLun(rqLun), rsSA(rsSA), seq(seq),
    rsLun(rsLun), cmd(cmd), completionCode(completionCode)
{
    data.reserve(ipmbMaxDataSize);

    if (inputData.size() > 0)
    {
        data = std::move(inputData);
    }
}

void IpmbResponse::ipmbToi2cConstruct(uint8_t* buffer, size_t* bufferLength)
{
    ipmbHeader* ipmbBuffer = (ipmbHeader*)buffer;

    ipmbBuffer->Header.Resp.address = address;
    ipmbBuffer->Header.Resp.rqNetFnLUN = ipmbNetFnLunSet(netFn, rqLun);
    ipmbBuffer->Header.Resp.rsSA = rsSA;
    ipmbBuffer->Header.Resp.rsSeqLUN = ipmbSeqLunSet(seq, rsLun);
    ipmbBuffer->Header.Resp.cmd = cmd;
    ipmbBuffer->Header.Resp.completionCode = completionCode;

    ipmbBuffer->Header.Resp.checksum1 = ipmbChecksumCompute(
        buffer, ipmbConnectionHeaderLength - ipmbChecksumSize);

    if (data.size() > 0)
    {
        std::copy(
            data.begin(), data.end(),
            &buffer[ipmbConnectionHeaderLength + ipmbResponseDataHeaderLength]);
    }

    *bufferLength = data.size() + ipmbResponseDataHeaderLength +
                    ipmbConnectionHeaderLength + ipmbChecksumSize;

    buffer[*bufferLength - ipmbChecksumSize] =
        ipmbChecksumCompute(&buffer[ipmbChecksum2StartOffset],
                            (ipmbResponseDataHeaderLength + data.size()));
}

void IpmbRequest::prepareRequest(sdbusplus::message_t& mesg)
{
    mesg.append(ipmbMeChannelNum, netFn, rqLun, cmd, data);
}

static constexpr unsigned int makeCmdKey(unsigned int netFn, unsigned int cmd)
{
    return (netFn << 8) | cmd;
}

static constexpr bool isMeCmdAllowed(uint8_t netFn, uint8_t cmd)
{
    constexpr uint8_t netFnMeOEM = 0x2E;
    constexpr uint8_t netFnMeOEMGeneral = 0x3E;
    constexpr uint8_t cmdMeOemSendRawPeci = 0x40;
    constexpr uint8_t cmdMeOemAggSendRawPeci = 0x41;
    constexpr uint8_t cmdMeOemCpuPkgConfWrite = 0x43;
    constexpr uint8_t cmdMeOemCpuPciConfWrite = 0x45;
    constexpr uint8_t cmdMeOemReadMemSmbus = 0x47;
    constexpr uint8_t cmdMeOemWriteMemSmbus = 0x48;
    constexpr uint8_t cmdMeOemSlotIpmb = 0x51;
    constexpr uint8_t cmdMeOemSlotI2cControllerWriteRead = 0x52;
    constexpr uint8_t cmdMeOemSendRawPmbus = 0xD9;
    constexpr uint8_t cmdMeOemUnlockMeRegion = 0xE7;
    constexpr uint8_t cmdMeOemAggSendRawPmbus = 0xEC;

    switch (makeCmdKey(netFn, cmd))
    {
        // Restrict ME Controller write command
        case makeCmdKey(ipmi::netFnApp, ipmi::app::cmdMasterWriteRead):
        // Restrict ME OEM commands
        case makeCmdKey(netFnMeOEM, cmdMeOemSendRawPeci):
        case makeCmdKey(netFnMeOEM, cmdMeOemAggSendRawPeci):
        case makeCmdKey(netFnMeOEM, cmdMeOemCpuPkgConfWrite):
        case makeCmdKey(netFnMeOEM, cmdMeOemCpuPciConfWrite):
        case makeCmdKey(netFnMeOEM, cmdMeOemReadMemSmbus):
        case makeCmdKey(netFnMeOEM, cmdMeOemWriteMemSmbus):
        case makeCmdKey(netFnMeOEMGeneral, cmdMeOemSlotIpmb):
        case makeCmdKey(netFnMeOEMGeneral, cmdMeOemSlotI2cControllerWriteRead):
        case makeCmdKey(netFnMeOEM, cmdMeOemSendRawPmbus):
        case makeCmdKey(netFnMeOEM, cmdMeOemUnlockMeRegion):
        case makeCmdKey(netFnMeOEM, cmdMeOemAggSendRawPmbus):
            return false;
        default:
            return true;
    }
}

ipmi::Cc Bridging::handleIpmbChannel(
    ipmi::Context::ptr& ctx, const uint8_t tracking,
    const std::vector<uint8_t>& msgData, std::vector<uint8_t>& rspData)
{
    ipmi::Manufacturing mtm;

    size_t msgLen = msgData.size();
    if ((msgLen < ipmbMinFrameLength) || (msgLen > ipmbMaxFrameLength))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "handleIpmbChannel, IPMB data length is invalid");
        return ipmi::ccReqDataLenInvalid;
    }

    // Bridging to ME requires Administrator lvl
    if ((ctx->priv) != ipmi::Privilege::Admin)
    {
        return ipmi::ccInsufficientPrivilege;
    }

    auto sendMsgReqData = reinterpret_cast<const ipmbHeader*>(msgData.data());

    // allow bridging to ME only
    if (sendMsgReqData->Header.Req.address != ipmbMeTargetAddress)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "handleIpmbChannel, IPMB address invalid");
        return ipmi::ccParmOutOfRange;
    }

    constexpr uint8_t shiftLUN = 2;
    if (mtm.getMfgMode() == ipmi::SpecialMode::none)
    {
        if (!isMeCmdAllowed((sendMsgReqData->Header.Req.rsNetFnLUN >> shiftLUN),
                            sendMsgReqData->Header.Req.cmd))
        {
            constexpr ipmi::Cc ccCmdNotSupportedInPresentState = 0xD5;
            return ccCmdNotSupportedInPresentState;
        }
    }

    // check allowed modes
    if (tracking != modeNoTracking && tracking != modeTrackRequest)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "handleIpmbChannel, mode not supported");
        return ipmi::ccParmOutOfRange;
    }

    // check if request contains valid IPMB frame
    if (!isFrameValid(sendMsgReqData, msgLen))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "handleIpmbChannel, IPMB frame invalid");
        return ipmi::ccParmOutOfRange;
    }

    auto ipmbRequest = IpmbRequest(sendMsgReqData, msgLen);

    typedef std::tuple<int, uint8_t, uint8_t, uint8_t, uint8_t,
                       std::vector<uint8_t>>
        IPMBResponse;

    // send request to IPMB
    boost::system::error_code ec;
    auto ipmbResponse = ctx->bus->yield_method_call<IPMBResponse>(
        ctx->yield, ec, ipmbBus, ipmbObj, ipmbIntf, "sendRequest",
        ipmbMeChannelNum, ipmbRequest.netFn, ipmbRequest.rqLun, ipmbRequest.cmd,
        ipmbRequest.data);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "handleIpmbChannel, dbus call exception");
        return ipmi::ccUnspecifiedError;
    }

    std::vector<uint8_t> dataReceived(0);
    int status = -1;
    uint8_t netFn = 0, lun = 0, cmd = 0, cc = 0;

    std::tie(status, netFn, lun, cmd, cc, dataReceived) = ipmbResponse;

    auto respReceived =
        IpmbResponse(ipmbRequest.rqSA, netFn, lun, ipmbRequest.address,
                     ipmbRequest.seq, lun, cmd, cc, dataReceived);

    // check IPMB layer status
    if (status)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "handleIpmbChannel, ipmb returned non zero status");
        return ipmi::ccResponseError;
    }

    switch (tracking)
    {
        case modeNoTracking:
        {
            if (getResponseQueueSize() == responseQueueMaxSize)
            {
                return ipmi::ccBusy;
            }
            insertMessageInQueue(respReceived);
            break;
        }
        case modeTrackRequest:
        {
            size_t dataLength = 0;
            respReceived.ipmbToi2cConstruct(rspData.data(), &dataLength);
            // resizing the rspData to its correct length
            rspData.resize(dataLength);
            break;
        }
        default:
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "handleIpmbChannel, mode not supported");
            return ipmi::ccParmOutOfRange;
        }
    }

    return ipmi::ccSuccess;
}

void Bridging::insertMessageInQueue(IpmbResponse msg)
{
    responseQueue.insert(responseQueue.end(), std::move(msg));
}

void Bridging::eraseMessageFromQueue()
{
    responseQueue.erase(responseQueue.begin());
}

IpmbResponse Bridging::getMessageFromQueue()
{
    return responseQueue.front();
}

/**
 * @brief This command is used for bridging ipmi message between channels.
 * @param channelNumber         - channel number to send message to
 * @param authenticationEnabled - authentication.
 * @param encryptionEnabled     - encryption
 * @param Tracking              - track request
 * @param msg                   - message data
 *
 * @return IPMI completion code plus response data on success.
 * - rspData - response data
 **/
ipmi::RspType<std::vector<uint8_t> // responseData
              >
    ipmiAppSendMessage(ipmi::Context::ptr& ctx, const uint4_t channelNumber,
                       const bool authenticationEnabled,
                       const bool encryptionEnabled, const uint2_t tracking,
                       ipmi::message::Payload& msg)
{
    // check message fields:
    // encryption not supported
    if (encryptionEnabled)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "ipmiAppSendMessage, encryption not supported");
        return ipmi::responseParmOutOfRange();
    }

    // authentication not supported
    if (authenticationEnabled)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "ipmiAppSendMessage, authentication not supported");
        return ipmi::responseParmOutOfRange();
    }

    ipmi::Cc returnVal;
    std::vector<uint8_t> rspData(ipmbMaxFrameLength);
    std::vector<uint8_t> unpackMsg;

    auto channelNo = static_cast<uint8_t>(channelNumber);
    // Get the channel number
    switch (channelNo)
    {
        // we only handle ipmb for now
        case targetChannelIpmb1:
        case targetChannelIpmb2:
        case targetChannelIpmb3:
            if (msg.unpack(unpackMsg) || !msg.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }

            returnVal = bridging.handleIpmbChannel(
                ctx, static_cast<uint8_t>(tracking), unpackMsg, rspData);
            break;
        // fall through to default
        case targetChannelIcmb10:
        case targetChannelIcmb09:
        case targetChannelLan:
        case targetChannelSerialModem:
        case targetChannelPciSmbus:
        case targetChannelSmbus10:
        case targetChannelSmbus20:
        case targetChannelSystemInterface:
        default:
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "ipmiAppSendMessage, TargetChannel invalid");
            return ipmi::responseParmOutOfRange();
    }
    if (returnVal != ipmi::ccSuccess)
    {
        return ipmi::response(returnVal);
    }

    return ipmi::responseSuccess(rspData);
}

/**
 * @brief This command is used to Get data from the receive message queue.
 *  This command should be executed executed via system interface only.
 *
 * @return IPMI completion code plus response data on success.
 * - channelNumber
 * - messageData
 **/

ipmi::RspType<uint8_t,             // channelNumber
              std::vector<uint8_t> // messageData
              >
    ipmiAppGetMessage(ipmi::Context::ptr& ctx)
{
    ipmi::ChannelInfo chInfo;

    try
    {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiAppGetMessage: Failed to get Channel Info",
            phosphor::logging::entry("MSG: %s", e.description()));
        return ipmi::responseUnspecifiedError();
    }
    if (chInfo.mediumType !=
        static_cast<uint8_t>(ipmi::EChannelMediumType::systemInterface))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiAppGetMessage: Error - supported only in System(SMS) "
            "interface");
        return ipmi::responseCommandNotAvailable();
    }

    uint8_t channelData = 0;
    std::vector<uint8_t> res(ipmbMaxFrameLength);
    size_t dataLength = 0;

    if (!bridging.getResponseQueueSize())
    {
        constexpr ipmi::Cc ipmiGetMessageCmdDataNotAvailable = 0x80;
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "ipmiAppGetMessage, no data available");
        return ipmi::response(ipmiGetMessageCmdDataNotAvailable);
    }

    // channel number set.
    channelData |= static_cast<uint8_t>(targetChannelSystemInterface) & 0x0F;

    // Priviledge level set.
    channelData |= SYSTEM_INTERFACE & 0xF0;

    // Get the first message from queue
    auto respQueueItem = bridging.getMessageFromQueue();

    // construct response data.
    respQueueItem.ipmbToi2cConstruct(res.data(), &dataLength);

    // Remove the message from queue
    bridging.eraseMessageFromQueue();

    // resizing the rspData to its correct length
    res.resize(dataLength);

    return ipmi::responseSuccess(channelData, res);
}

std::size_t Bridging::getResponseQueueSize()
{
    return responseQueue.size();
}

/**
@brief This command is used to retrive present message available states.

@return IPMI completion code plus Flags as response data on success.
**/
ipmi::RspType<std::bitset<8>> ipmiAppGetMessageFlags(ipmi::Context::ptr& ctx)
{
    ipmi::ChannelInfo chInfo;

    try
    {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiAppGetMessageFlags: Failed to get Channel Info",
            phosphor::logging::entry("MSG: %s", e.description()));
        return ipmi::responseUnspecifiedError();
    }
    if (chInfo.mediumType !=
        static_cast<uint8_t>(ipmi::EChannelMediumType::systemInterface))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiAppGetMessageFlags: Error - supported only in System(SMS) "
            "interface");
        return ipmi::responseCommandNotAvailable();
    }

    std::bitset<8> getMsgFlagsRes;

    // set event message buffer bit
    if (!eventMessageBufferFlag)
    {
        getMsgFlagsRes.set(getMsgFlagEventMessageBit);
    }
    else
    {
        getMsgFlagsRes.reset(getMsgFlagEventMessageBit);
    }

    // set message fields
    if (bridging.getResponseQueueSize() > 0)
    {
        getMsgFlagsRes.set(getMsgFlagReceiveMessageBit);
    }
    else
    {
        getMsgFlagsRes.reset(getMsgFlagReceiveMessageBit);
    }

    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        ipmi::Value variant = ipmi::getDbusProperty(
            *dbus, wdtService, wdtObjPath, wdtInterface, wdtInterruptFlagProp);
        if (std::get<bool>(variant))
        {
            getMsgFlagsRes.set(getMsgFlagWatchdogPreTimeOutBit);
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiAppGetMessageFlags, dbus call exception");
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(getMsgFlagsRes);
}

/** @brief This command is used to flush unread data from the receive
 *   message queue
 *  @param receiveMessage  - clear receive message queue
 *  @param eventMsgBufFull - clear event message buffer full
 *  @param reserved2       - reserved bit
 *  @param watchdogTimeout - clear watchdog pre-timeout interrupt flag
 *  @param reserved1       - reserved bit
 *  @param oem0            - clear OEM 0 data
 *  @param oem1            - clear OEM 1 data
 *  @param oem2            - clear OEM 2 data

 *  @return IPMI completion code on success
 */
ipmi::RspType<> ipmiAppClearMessageFlags(
    ipmi::Context::ptr& ctx, bool receiveMessage, bool eventMsgBufFull,
    bool reserved2, bool watchdogTimeout, bool reserved1, bool /* oem0 */,
    bool /* oem1 */, bool /* oem2 */)
{
    ipmi::ChannelInfo chInfo;

    try
    {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiAppClearMessageFlags: Failed to get Channel Info",
            phosphor::logging::entry("MSG: %s", e.description()));
        return ipmi::responseUnspecifiedError();
    }
    if (chInfo.mediumType !=
        static_cast<uint8_t>(ipmi::EChannelMediumType::systemInterface))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiAppClearMessageFlags: Error - supported only in System(SMS) "
            "interface");
        return ipmi::responseCommandNotAvailable();
    }

    if (reserved1 || reserved2)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (receiveMessage)
    {
        bridging.clearResponseQueue();
    }

    if (eventMessageBufferFlag != true && eventMsgBufFull == true)
    {
        eventMessageBufferFlag = true;
    }

    try
    {
        if (watchdogTimeout)
        {
            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            ipmi::setDbusProperty(*dbus, wdtService, wdtObjPath, wdtInterface,
                                  wdtInterruptFlagProp, false);
        }
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiAppClearMessageFlags: can't Clear/Set "
            "PreTimeoutInterruptOccurFlag");
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

using systemEventType = std::tuple<
    uint16_t, // Generator ID
    uint32_t, // Timestamp
    uint8_t,  // Sensor Type
    uint8_t,  // EvM Rev
    uint8_t,  // Sensor Number
    uint7_t,  // Event Type
    bool,     // Event Direction
    std::array<uint8_t, intel_oem::ipmi::sel::systemEventSize>>; // Event Data
using oemTsEventType = std::tuple<
    uint32_t,                                                    // Timestamp
    std::array<uint8_t, intel_oem::ipmi::sel::oemTsEventSize>>;  // Event Data
using oemEventType =
    std::array<uint8_t, intel_oem::ipmi::sel::oemEventSize>;     // Event Data

std::pair<std::string, std::string> parseEntries(const std::string& entry)
{
    constexpr auto equalSign = "=";
    auto pos = entry.find(equalSign);
    assert(pos != std::string::npos);
    auto key = entry.substr(0, pos);
    auto val = entry.substr(pos + 1);
    return {key, val};
}

uint8_t convertData(const std::string_view& str, int base = 10)
{
    int ret;
    std::from_chars(str.data(), str.data() + str.size(), ret, base);
    return static_cast<uint8_t>(ret);
}

// Converts a hex string to a vector of uint8_t values.
std::vector<uint8_t> convertVector(const std::string_view& str)
{
    std::vector<uint8_t> ret;
    auto len = str.size() / 2;
    ret.reserve(len);
    for (size_t i = 0; i < len; ++i)
    {
        // Convert the next two-character hex substring to a uint8_t value and
        // append it to the vector.
        ret.emplace_back(convertData(str.substr(i * 2, 2), 16));
    }
    return ret;
}

/** @brief implements of Read event message buffer command
 *
 *  @returns IPMI completion code plus response data
 *   - recordID - SEL Record ID
 *   - recordType - Record Type
 *   - generatorID - Generator ID
 *   - timeStamp - Timestamp
 *   - sensorType - Sensor Type
 *   - eventMsgFormatRev - Event Message format version
 *   - sensorNumber - Sensor Number
 *   - eventType - Event Type
 *   - eventDir - Event Direction
 *   - eventData - Event Data field
 */
ipmi::RspType<uint16_t,             // Record ID
              uint8_t,              // Record Type
              uint64_t,             // Timestamp
              uint16_t,             // Generator ID
              uint8_t,              // EVM Rev
              uint8_t,              // Sensor Type
              uint8_t,              // Sensor Number
              uint8_t,              // Event Dir
              std::vector<uint8_t>> // EventData
    ipmiAppReadEventMessageBuffer(ipmi::Context::ptr& ctx)
{
    std::string lastEntryPath;
    ipmi::ChannelInfo chInfo;
    try
    {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiAppReadEventMessageBuffer: Failed to get Channel Info",
            phosphor::logging::entry("MSG: %s", e.description()));
        return ipmi::responseUnspecifiedError();
    }
    if (chInfo.mediumType !=
        static_cast<uint8_t>(ipmi::EChannelMediumType::systemInterface))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiAppReadEventMessageBuffer: Error - supported only in "
            "System(SMS) interface");
        return ipmi::responseCommandNotAvailable();
    }
    auto bus = sdbusplus::bus::new_default();
    bool eventMsgBuf;
    auto method = bus.new_method_call(settingService, globalEnblObjpath,
                                      "org.freedesktop.DBus.Properties", "Get");
    // Append the interface and property name to the method call
    method.append(globalEnblInterface, "EventmsgBuf");
    try
    {
        auto reply = bus.call(method);
        // Extract the value from the response
        std::variant<bool> value;
        reply.read(value);
        eventMsgBuf = std::get<bool>(value);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get EventMsgBuffer Property",
            phosphor::logging::entry("ERROR=%s", e.what()));
        eventMsgBuf = false;
    }
    if (eventMsgBuf != false)
    {
        auto mapperCall = bus.new_method_call(
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTree");
        constexpr const auto depth = 2;
        constexpr std::array<const char*, 1> interface = {
            "xyz.openbmc_project.Logging.Entry"};
        mapperCall.append("/xyz/openbmc_project/logging", depth, interface);
        try
        {
            auto mapperReply = bus.call(mapperCall);
            std::map<std::string,
                     std::map<std::string, std::vector<std::string>>>
                subtree;
            mapperReply.read(subtree);
            std::vector<std::string> entryPaths;

            for (const auto& [path, object] : subtree)
            {
                entryPaths.push_back(path);
            }
            if (entryPaths.empty())
            {
                return ipmi::responseNodataAvailablequeuebufferEmpty();
            }
            // Sorting the entries to get the last entry
            std::sort(entryPaths.begin(), entryPaths.end());

            lastEntryPath = entryPaths.back();
        }
        catch (const std::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to call SEL Entries method",
                phosphor::logging::entry("ERROR=%s", e.what()));
            return ipmi::responseUnspecifiedError();
        }
        std::variant<std::vector<std::string>> entryData;
        //  Read all the log entry properties.
        auto methodCall =
            bus.new_method_call(loggingService, lastEntryPath.c_str(),
                                "org.freedesktop.DBus.Properties", "Get");
        methodCall.append("xyz.openbmc_project.Logging.Entry",
                          "AdditionalData");
        auto reply = bus.call(methodCall);
        reply.read(entryData);
        if (reply.is_method_error())
        {
            return ipmi::responseUnspecifiedError();
        }
        std::vector<std::string> Data =
            std::get<std::vector<std::string>>(entryData);
        std::map<std::string, std::string> ret;
        for (const auto& d : Data)
        {
            ret.insert(parseEntries(d));
        }
        std::map<std::string, std::variant<uint16_t, uint64_t>> SelIdtimestamp;
        auto method = bus.new_method_call(loggingService, lastEntryPath.c_str(),
                                          "org.freedesktop.DBus.Properties",
                                          "GetAll");
        method.append("xyz.openbmc_project.Logging.Entry");
        auto resp = bus.call(method);
        resp.read(SelIdtimestamp);
        if (resp.is_method_error())
        {
            return ipmi::responseUnspecifiedError();
        }
        auto recordId = std::get<uint16_t>(SelIdtimestamp["Id"]);
        auto timestamp = std::get<uint64_t>(SelIdtimestamp["Timestamp"]);
        auto recordType = static_cast<uint8_t>(convertData(ret[recordTypestr]));
        auto eventDir = static_cast<uint8_t>(convertData(ret[eventDirstr]));
        auto generatorId =
            static_cast<uint16_t>(convertData(ret[generateIdstr]));
        std::vector<uint8_t> sensorData = (convertVector(ret[sensorEventData]));
        auto sensorType = static_cast<uint8_t>(convertData(ret[sensorTypestr]));
        constexpr uint8_t eventMsgFormatRev = 0x3A;
        constexpr uint8_t sensorNumber = 0xFF;

        return ipmi::responseSuccess(recordId, recordType, timestamp,
                                     generatorId, eventMsgFormatRev, sensorType,
                                     sensorNumber, eventDir, sensorData);
    }
    else
    {
        return ipmi::responseCommandDisabled();
    }
}

static void register_bridging_functions() __attribute__((constructor));
static void register_bridging_functions()
{
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnApp,
                          ipmi::app::cmdClearMessageFlags,
                          ipmi::Privilege::User, ipmiAppClearMessageFlags);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnApp,
                          ipmi::app::cmdGetMessageFlags, ipmi::Privilege::User,
                          ipmiAppGetMessageFlags);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnApp,
                          ipmi::app::cmdGetMessage, ipmi::Privilege::User,
                          ipmiAppGetMessage);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnApp,
                          ipmi::app::cmdSendMessage, ipmi::Privilege::User,
                          ipmiAppSendMessage);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnApp,
                          ipmi::app::cmdReadEventMessageBuffer,
                          ipmi::Privilege::User, ipmiAppReadEventMessageBuffer);

    return;
}

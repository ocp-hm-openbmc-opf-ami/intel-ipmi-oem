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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <commandutils.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <oemcommands.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <smbiosmdrv2handler.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

std::unique_ptr<MDRV2> mdrv2 = nullptr;
static constexpr const uint8_t ccOemInvalidChecksum = 0x85;
static constexpr size_t dataInfoSize = 16;
static constexpr const uint8_t ccStorageLeak = 0xC4;

static void register_netfn_smbiosmdrv2_functions() __attribute__((constructor));

int MDRV2::agentLookup(const uint16_t& agentId)
{
    int agentIndex = -1;

    if (lastAgentId == agentId)
    {
        currentAgentIndex = lastAgentIndex;
        return lastAgentIndex;
    }
    if (agentId == smbiosAgentId)
    {
        currentAgentIndex = firstAgentIndex;
        return firstAgentIndex;
    }
    else if (agentId == acpiAgentId)
    {
        currentAgentIndex = acpiAgentIndex;
        return acpiAgentIndex;
    }
    return agentIndex;
}

int MDRV2::sdplusMdrv2GetProperty(const std::string& name,
                                  ipmi::DbusVariant& value,
                                  const std::string& service)
{
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    sdbusplus::message_t method = bus->new_method_call(
        service.c_str(), mdrv2Dir[currentAgentIndex].mdrv2Path, dbusProperties,
        "Get");
    method.append(mdrv2Dir[currentAgentIndex].mdrv2Interface, name);
    sdbusplus::message_t reply = bus->call(method);
    try
    {
        sdbusplus::message_t reply = bus->call(method);
        reply.read(value);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get property, sdbusplus call failed",
            phosphor::logging::entry("ERROR=%s", e.what()));
        return -1;
    }

    return 0;
}

int MDRV2::syncDirCommonData(int agentIndex, uint8_t idIndex, uint32_t size,
                             const std::string& service)
{
    std::vector<uint32_t> commonData;
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    sdbusplus::message_t method = bus->new_method_call(
        service.c_str(), mdrv2Dir[currentAgentIndex].mdrv2Path,
        mdrv2Dir[currentAgentIndex].mdrv2Interface,
        "SynchronizeDirectoryCommonData");
    method.append(idIndex, size);

    try
    {
        sdbusplus::message_t reply = bus->call(method);
        reply.read(commonData);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error sync dir common data with service",
            phosphor::logging::entry("ERROR=%s", e.what()));
        return -1;
    }

    if (commonData.size() < syncDirCommonSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error sync dir common data - data length invalid");
        return -1;
    }
    mdrv2Dir[agentIndex].dir[idIndex].common.dataSetSize = commonData.at(0);
    mdrv2Dir[agentIndex].dir[idIndex].common.dataVersion = commonData.at(1);
    mdrv2Dir[agentIndex].dir[idIndex].common.timestamp = commonData.at(2);

    return 0;
}

int MDRV2::findDataId(const uint8_t* dataInfo, const size_t& len,
                      const std::string& service)
{
    int idIndex = -1;

    if (dataInfo == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error dataInfo, input is null point");
        return -1;
    }

    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    sdbusplus::message_t method = bus->new_method_call(
        service.c_str(), mdrv2Dir[currentAgentIndex].mdrv2Path,
        mdrv2Dir[currentAgentIndex].mdrv2Interface, "FindIdIndex");
    std::vector<uint8_t> info;
    info.resize(len);
    std::copy(dataInfo, dataInfo + len, info.data());
    method.append(info);

    try
    {
        sdbusplus::message_t reply = bus->call(method);
        reply.read(idIndex);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error find id index",
            phosphor::logging::entry("ERROR=%s", e.what()),
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s",
                                     mdrv2Dir[currentAgentIndex].mdrv2Path));
        return -1;
    }

    return idIndex;
}

uint16_t MDRV2::getSessionHandle(Mdr2DirStruct* dir)
{
    if (dir == NULL)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Empty dir point");
        return 0;
    }
    dir->sessionHandle++;
    if (dir->sessionHandle == 0)
    {
        dir->sessionHandle = 1;
    }

    return dir->sessionHandle;
}

int MDRV2::findLockHandle(int agentIndex, const uint16_t& lockHandle)
{
    int idIndex = -1;

    for (int index = 0; index < mdrv2Dir[agentIndex].dirEntries; index++)
    {
        if (lockHandle == mdrv2Dir[agentIndex].dir[index].lockHandle)
        {
            return index;
        }
    }

    return idIndex;
}

bool MDRV2::smbiosIsUpdating(int agentIndex, uint8_t index)
{
    if (index >= maxDirEntries)
    {
        return false;
    }
    if (mdrv2Dir[agentIndex].dir[index].stage ==
        MDR2SMBIOSStatusEnum::mdr2Updating)
    {
        return true;
    }

    return false;
}

uint32_t MDRV2::calcChecksum32(uint8_t* buf, uint32_t len)
{
    uint32_t sum = 0;

    if (buf == nullptr)
    {
        return invalidChecksum;
    }

    for (uint32_t index = 0; index < len; index++)
    {
        sum += buf[index];
    }

    return sum;
}

/** @brief implements mdr2 agent status command
 *  @param agentId
 *  @param dirVersion
 *
 *  @returns IPMI completion code plus response data
 *  - mdrVersion
 *  - agentVersion
 *  - dirVersion
 *  - dirEntries
 *  - dataRequest
 */
ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t, uint8_t>
    mdr2AgentStatus(uint16_t agentId, uint8_t dirVersion)
{
    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    constexpr uint8_t mdrVersion = mdr2Version;
    constexpr uint8_t agentVersion = smbiosAgentVersion;
    uint8_t dirVersionResp = mdrv2->mdrv2Dir[agentIndex].dirVersion;
    uint8_t dirEntries = mdrv2->mdrv2Dir[agentIndex].dirEntries;
    uint8_t dataRequest;

    if (mdrv2->mdrv2Dir[agentIndex].remoteDirVersion != dirVersion)
    {
        mdrv2->mdrv2Dir[agentIndex].remoteDirVersion = dirVersion;
        dataRequest =
            static_cast<uint8_t>(DirDataRequestEnum::dirDataRequested);
    }
    else
    {
        dataRequest =
            static_cast<uint8_t>(DirDataRequestEnum::dirDataNotRequested);
    }

    return ipmi::responseSuccess(mdrVersion, agentVersion, dirVersionResp,
                                 dirEntries, dataRequest);
}

/** @brief implements mdr2 get directory command
 *  @param agentId
 *  @param dirIndex
 *  @returns IPMI completion code plus response data
 *  - dataOut
 */
ipmi::RspType<std::vector<uint8_t>>
    mdr2GetDir(uint16_t agentId, uint8_t dirIndex)
{
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    ipmi::DbusVariant value = static_cast<uint8_t>(0);
    if (mdrv2->mdrv2Dir[agentIndex].overrideFlag ||
        mdrv2->mdrv2Dir[agentIndex].mdrv2Interface == nullptr ||
        mdrv2->mdrv2Dir[agentIndex].mdrv2Path == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Current agent dont support a service to store the dir information",
            phosphor::logging::entry("AGENT=%x", agentIndex));
        return ipmi::responseUnspecifiedError();
    }
    std::string service =
        ipmi::getService(*bus, mdrv2->mdrv2Dir[agentIndex].mdrv2Interface,
                         mdrv2->mdrv2Dir[agentIndex].mdrv2Path);
    if (0 != mdrv2->sdplusMdrv2GetProperty("DirectoryEntries", value, service))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error getting DirEnries");
        return ipmi::responseUnspecifiedError();
    }
    if (std::get<uint8_t>(value) == 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error getting directory entries",
            phosphor::logging::entry("VALUE=%x", std::get<uint8_t>(value)));
        return ipmi::responseUnspecifiedError();
    }
    if (dirIndex > std::get<uint8_t>(value))
    {
        return ipmi::responseParmOutOfRange();
    }

    sdbusplus::message_t method = bus->new_method_call(
        service.c_str(), mdrv2->mdrv2Dir[agentIndex].mdrv2Path,
        mdrv2->mdrv2Dir[agentIndex].mdrv2Interface, "GetDirectoryInformation");

    method.append(dirIndex);

    std::vector<uint8_t> dataOut;
    try
    {
        sdbusplus::message_t reply = bus->call(method);
        reply.read(dataOut);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get dir", phosphor::logging::entry("ERROR=%s", e.what()),
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s",
                                     mdrv2->mdrv2Dir[agentIndex].mdrv2Path));
        return ipmi::responseResponseError();
    }

    constexpr size_t getDirRespSize = 6;
    if (dataOut.size() < getDirRespSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get dir, response length invalid");
        return ipmi::responseUnspecifiedError();
    }

    if (dataOut.size() > MAX_IPMI_BUFFER) // length + completion code should no
                                          // more than MAX_IPMI_BUFFER
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Data length send from service is invalid");
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(dataOut);
}

/** @brief implements mdr2 send directory info command
 *  @param agentId
 *  @param dirVersion
 *  @param dirIndex
 *  @param returnedEntries
 *  @param remainingEntries
 *  @param dataInfo
 *   dataInfo is 32 Bytes in size and contains below parameters
 *       - dataInfo, size, dataSetSize, dataVersion, timestamp
 *
 *  @returns IPMI completion code plus response data
 *  - bool
 */

ipmi::RspType<bool>
    mdr2SendDir(uint16_t agentId, uint8_t dirVersion, uint8_t dirIndex,
                uint8_t returnedEntries, uint8_t remainingEntries,
                std::vector<uint8_t> dataInfo)
{
    if ((static_cast<size_t>(returnedEntries) * dataInfoSize) !=
        dataInfo.size())
    {
        return ipmi::responseReqDataLenInvalid();
    }

    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    if (mdrv2->mdrv2Dir[agentIndex].overrideFlag ||
        mdrv2->mdrv2Dir[agentIndex].mdrv2Interface == nullptr ||
        mdrv2->mdrv2Dir[agentIndex].mdrv2Path == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Current agent dont support a service to store the dir information",
            phosphor::logging::entry("AGENT=%x", agentIndex));
        return ipmi::responseUnspecifiedError();
    }
    std::string service =
        ipmi::getService(*bus, mdrv2->mdrv2Dir[agentIndex].mdrv2Interface,
                         mdrv2->mdrv2Dir[agentIndex].mdrv2Path);

    if ((dirIndex + returnedEntries) > maxDirEntries)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Too many directory entries");
        return ipmi::response(ccStorageLeak);
    }

    sdbusplus::message_t method = bus->new_method_call(
        service.c_str(), mdrv2->mdrv2Dir[agentIndex].mdrv2Path,
        mdrv2->mdrv2Dir[agentIndex].mdrv2Interface, "SendDirectoryInformation");
    method.append(dirVersion, dirIndex, returnedEntries, remainingEntries,
                  dataInfo);

    bool terminate = false;
    try
    {
        sdbusplus::message_t reply = bus->call(method);
        reply.read(terminate);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error send dir", phosphor::logging::entry("ERROR=%s", e.what()),
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s",
                                     mdrv2->mdrv2Dir[agentIndex].mdrv2Path));
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(terminate);
}

/** @brief implements mdr2 get data info command
 *  @param agentId
 *  @param dataInfo
 *
 *  @returns IPMI completion code plus response data
 *  - response - mdrVersion, data info, validFlag,
 *               dataLength, dataVersion, timeStamp
 */
ipmi::RspType<std::vector<uint8_t>>
    mdr2GetDataInfo(uint16_t agentId, std::vector<uint8_t> dataInfo)
{
    constexpr size_t getDataInfoReqSize = 16;

    if (dataInfo.size() < getDataInfoReqSize)
    {
        return ipmi::responseReqDataLenInvalid();
    }

    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    if (mdrv2->mdrv2Dir[agentIndex].overrideFlag ||
        mdrv2->mdrv2Dir[agentIndex].mdrv2Interface == nullptr ||
        mdrv2->mdrv2Dir[agentIndex].mdrv2Path == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Current agent dont support a service to store the dir information",
            phosphor::logging::entry("AGENT=%x", agentIndex));
        return ipmi::responseUnspecifiedError();
    }
    std::string service =
        ipmi::getService(*bus, mdrv2->mdrv2Dir[agentIndex].mdrv2Interface,
                         mdrv2->mdrv2Dir[agentIndex].mdrv2Path);

    int idIndex = mdrv2->findDataId(dataInfo.data(), dataInfo.size(), service);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return ipmi::responseParmOutOfRange();
    }

    sdbusplus::message_t method = bus->new_method_call(
        service.c_str(), mdrv2->mdrv2Dir[agentIndex].mdrv2Path,
        mdrv2->mdrv2Dir[agentIndex].mdrv2Interface, "GetDataInformation");

    method.append(static_cast<uint8_t>(idIndex));

    std::vector<uint8_t> res;
    try
    {
        sdbusplus::message_t reply = bus->call(method);
        reply.read(res);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get data info",
            phosphor::logging::entry("ERROR=%s", e.what()),
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s",
                                     mdrv2->mdrv2Dir[agentIndex].mdrv2Path));
        return ipmi::responseResponseError();
    }

    if (res.size() != sizeof(MDRiiGetDataInfoResponse))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get data info response length not invalid");
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(res);
}

/** @brief implements mdr2 data info offer command
 *  @param agentId - Offer a agent ID to get the "Data Set ID"
 *
 *  @returns IPMI completion code plus response data
 *  - dataOut - data Set Id
 */
ipmi::RspType<std::vector<uint8_t>> mdr2DataInfoOffer(uint16_t agentId)
{
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    std::vector<uint8_t> dataOut;
    if (mdrv2->mdrv2Dir[agentIndex].overrideFlag ||
        mdrv2->mdrv2Dir[agentIndex].mdrv2Interface == nullptr ||
        mdrv2->mdrv2Dir[agentIndex].mdrv2Path == nullptr)
    {
        dataOut.resize(sizeof(DataIdStruct));
        std::copy(mdrv2->mdrv2Dir[agentIndex].dir[0].common.id.dataInfo,
                  &mdrv2->mdrv2Dir[agentIndex].dir[0].common.id.dataInfo[16],
                  dataOut.data());
        return ipmi::responseSuccess(dataOut);
    }
    std::string service =
        ipmi::getService(*bus, mdrv2->mdrv2Dir[agentIndex].mdrv2Interface,
                         mdrv2->mdrv2Dir[agentIndex].mdrv2Path);

    sdbusplus::message_t method = bus->new_method_call(
        service.c_str(), mdrv2->mdrv2Dir[agentIndex].mdrv2Path,
        mdrv2->mdrv2Dir[agentIndex].mdrv2Interface, "GetDataOffer");

    try
    {
        sdbusplus::message_t reply = bus->call(method);
        reply.read(dataOut);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error send data info offer",
            phosphor::logging::entry("ERROR=%s", e.what()),
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s",
                                     mdrv2->mdrv2Dir[agentIndex].mdrv2Path));
        return ipmi::responseResponseError();
    }

    constexpr size_t respInfoSize = 16;
    if (dataOut.size() != respInfoSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error send data info offer, return length invalid");
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(dataOut);
}

/** @brief implements mdr2 send data info command
 *  @param agentId
 *  @param dataInfo
 *  @param validFlag
 *  @param dataLength
 *  @param dataVersion
 *  @param timeStamp
 *
 *  @returns IPMI completion code plus response data
 *  - bool
 */
ipmi::RspType<bool> mdr2SendDataInfo(uint16_t agentId,
                                     std::array<uint8_t, dataInfoSize> dataInfo,
                                     uint8_t validFlag, uint32_t dataLength,
                                     uint32_t dataVersion, uint32_t timeStamp)
{
    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    if (dataLength > mdrv2->mdrv2Dir[agentIndex].dir[mdrv2DirIndex].maxDataSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Requested data length is out of Table storage size.");
        return ipmi::responseParmOutOfRange();
    }

    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();

    bool entryChanged = true;
    if (mdrv2->mdrv2Dir[agentIndex].overrideFlag ||
        mdrv2->mdrv2Dir[agentIndex].mdrv2Interface == nullptr ||
        mdrv2->mdrv2Dir[agentIndex].mdrv2Path == nullptr)
    {
        return ipmi::responseSuccess(entryChanged);
    }
    std::string service =
        ipmi::getService(*bus, mdrv2->mdrv2Dir[agentIndex].mdrv2Interface,
                         mdrv2->mdrv2Dir[agentIndex].mdrv2Path);

    int idIndex = mdrv2->findDataId(dataInfo.data(), dataInfo.size(), service);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return ipmi::responseParmOutOfRange();
    }

    sdbusplus::message_t method = bus->new_method_call(
        service.c_str(), mdrv2->mdrv2Dir[agentIndex].mdrv2Path,
        mdrv2->mdrv2Dir[agentIndex].mdrv2Interface, "SendDataInformation");

    method.append((uint8_t)idIndex, validFlag, dataLength, dataVersion,
                  timeStamp);

    try
    {
        sdbusplus::message_t reply = bus->call(method);
        reply.read(entryChanged);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error send data info",
            phosphor::logging::entry("ERROR=%s", e.what()),
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s",
                                     mdrv2->mdrv2Dir[agentIndex].mdrv2Path));
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(entryChanged);
}

/**
@brief This command is MDR related get data block command.

@param - agentId
@param - lockHandle
@param - xferOffset
@param - xferLength

@return on success
   - xferLength
   - checksum
   - data
**/
ipmi::RspType<uint32_t,            // xferLength
              uint32_t,            // Checksum
              std::vector<uint8_t> // data
              >
    mdr2GetDataBlock(uint16_t agentId, uint16_t lockHandle, uint32_t xferOffset,
                     uint32_t xferLength)
{
    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    int idIndex = mdrv2->findLockHandle(agentIndex, lockHandle);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return ipmi::responseParmOutOfRange();
    }

    if (xferOffset >= mdrv2->mdrv2Dir[agentIndex].dir[idIndex].common.size)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Offset is outside of range.");
        return ipmi::responseParmOutOfRange();
    }

    size_t outSize =
        (xferLength > mdrv2->mdrv2Dir[agentIndex].dir[idIndex].xferSize)
            ? mdrv2->mdrv2Dir[agentIndex].dir[idIndex].xferSize
            : xferLength;
    if (outSize > UINT_MAX - xferOffset)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Out size and offset are out of range");
        return ipmi::responseParmOutOfRange();
    }
    if ((xferOffset + outSize) >
        mdrv2->mdrv2Dir[agentIndex].dir[idIndex].common.size)
    {
        outSize = mdrv2->mdrv2Dir[agentIndex].dir[idIndex].common.size -
                  xferOffset;
    }

    uint32_t respXferLength = outSize;

    if (respXferLength > xferLength)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get data block unexpected error.");
        return ipmi::responseUnspecifiedError();
    }

    if ((xferOffset + outSize) >
        UINT_MAX - reinterpret_cast<size_t>(
                       mdrv2->mdrv2Dir[agentIndex].dir[idIndex].dataStorage))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Input data to calculate checksum is out of range");
        return ipmi::responseParmOutOfRange();
    }

    uint32_t u32Checksum = mdrv2->calcChecksum32(
        mdrv2->mdrv2Dir[agentIndex].dir[idIndex].dataStorage + xferOffset,
        outSize);
    if (u32Checksum == invalidChecksum)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get data block failed - invalid checksum");
        return ipmi::response(ccOemInvalidChecksum);
    }
    std::vector<uint8_t> data(outSize);

    std::copy(&mdrv2->mdrv2Dir[agentIndex].dir[idIndex].dataStorage[xferOffset],
              &mdrv2->mdrv2Dir[agentIndex].dir[idIndex].dataStorage[xferOffset +
                                                                    outSize],
              data.begin());

    return ipmi::responseSuccess(respXferLength, u32Checksum, data);
}

/** @brief implements mdr2 send data block command
 *  @param agentId
 *  @param lockHandle
 *  @param xferOffset
 *  @param xferLength
 *  @param checksum
 *
 *  @returns IPMI completion code
 */
ipmi::RspType<> mdr2SendDataBlock(uint16_t agentId, uint16_t lockHandle,
                                  uint32_t xferOffset, uint32_t xferLength,
                                  uint32_t checksum)
{
    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    int idIndex = mdrv2->findLockHandle(agentIndex, lockHandle);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return ipmi::responseParmOutOfRange();
    }

    if (mdrv2->smbiosIsUpdating(agentIndex, idIndex))
    {
        if (xferOffset > UINT_MAX - xferLength)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Offset and length are out of range");
            return ipmi::responseParmOutOfRange();
        }
        if (((xferOffset + xferLength) >
             mdrv2->mdrv2Dir[agentIndex].dir[idIndex].maxDataSize) ||
            ((xferOffset + xferLength) >
             mdrv2->mdrv2Dir[agentIndex].dir[idIndex].common.dataSetSize))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Send data block Invalid offset/length");
            return ipmi::responseReqDataLenExceeded();
        }
        if (reinterpret_cast<size_t>(
                mdrv2->mdrv2Dir[agentIndex].dir[idIndex].dataStorage) >
            UINT_MAX - xferOffset)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Offset is out of range");
            return ipmi::responseParmOutOfRange();
        }
        uint8_t* destAddr =
            mdrv2->smbiosDir.dir[idIndex].dataStorage + xferOffset;
        uint8_t* sourceAddr = reinterpret_cast<uint8_t*>(mdrv2->area->vPtr);
        uint32_t calcChecksum = mdrv2->calcChecksum32(sourceAddr, xferLength);
        if (calcChecksum != checksum)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Send data block Invalid checksum");
            return ipmi::response(ccOemInvalidChecksum);
        }
        else
        {
            if (reinterpret_cast<size_t>(sourceAddr) > UINT_MAX - xferLength)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Length is out of range");
                return ipmi::responseParmOutOfRange();
            }
            std::copy(sourceAddr, sourceAddr + xferLength, destAddr);
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Send data block failed, other data is updating");
        return ipmi::responseDestinationUnavailable();
    }

    return ipmi::responseSuccess();
}

bool MDRV2::storeDatatoFlash(int agentIndex, MDRSMBIOSHeader* mdrHdr,
                             uint8_t* data)
{
    std::ofstream smbiosFile(
        reinterpret_cast<char*>(mdrv2Dir[agentIndex].fileName),
        std::ios_base::binary | std::ios_base::trunc);
    if (!smbiosFile.good())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Write data from flash error - Open MDRV2 table file failure");
        return false;
    }

    try
    {
        smbiosFile.write(reinterpret_cast<char*>(mdrHdr),
                         sizeof(MDRSMBIOSHeader));
        smbiosFile.write(reinterpret_cast<char*>(data), mdrHdr->dataSize);
    }
    catch (const std::ofstream::failure& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Write data from flash error - write data error",
            phosphor::logging::entry("ERROR=%s", e.what()));
        return false;
    }

    return true;
}

void SharedMemoryArea::Initialize(uint32_t addr, uint32_t areaSize)
{
    int memDriver = 0;

    // open mem driver for the system memory access
    memDriver = open("/dev/vgasharedmem", O_RDONLY);
    if (memDriver < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Cannot access mem driver");
        throw std::system_error(EIO, std::generic_category());
    }

    // map the system memory
    vPtr = mmap(NULL,                       // where to map to: don't mind
                areaSize,                   // how many bytes ?
                PROT_READ,                  // want to read and write
                MAP_SHARED,                 // no copy on write
                memDriver,                  // handle to /dev/mem
                (physicalAddr & pageMask)); // hopefully the Text-buffer :-)

    close(memDriver);
    if (vPtr == MAP_FAILED)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to map share memory");
        throw std::system_error(EIO, std::generic_category());
    }
    size = areaSize;
    physicalAddr = addr;
}

bool MDRV2::smbiosUnlock(int agentIndex, uint8_t index)
{
    bool ret = false;
    switch (mdrv2Dir[agentIndex].dir[index].stage)
    {
        case MDR2SMBIOSStatusEnum::mdr2Updating:
            mdrv2Dir[agentIndex].dir[index].stage =
                MDR2SMBIOSStatusEnum::mdr2Updated;
            mdrv2Dir[agentIndex].dir[index].lock =
                MDR2DirLockEnum::mdr2DirUnlock;

            timer->stop();
            mdrv2Dir[agentIndex].dir[index].lockHandle = 0;
            ret = true;
            break;

        case MDR2SMBIOSStatusEnum::mdr2Updated:
        case MDR2SMBIOSStatusEnum::mdr2Loaded:
            mdrv2Dir[agentIndex].dir[index].lock =
                MDR2DirLockEnum::mdr2DirUnlock;

            timer->stop();

            mdrv2Dir[agentIndex].dir[index].lockHandle = 0;
            ret = true;
            break;

        default:
            break;
    }

    return ret;
}

bool MDRV2::smbiosTryLock(int agentIndex, uint8_t flag, uint8_t index,
                          uint16_t* session, uint16_t timeout)
{
    bool ret = false;

    if (timeout == 0)
    {
        timeout = defaultTimeout;
    }
    std::chrono::microseconds usec(timeout * sysClock);

    switch (mdrv2Dir[agentIndex].dir[index].stage)
    {
        case MDR2SMBIOSStatusEnum::mdr2Updating:
            if (mdrv2Dir[agentIndex].dir[index].lock !=
                MDR2DirLockEnum::mdr2DirLock)
            {
                mdrv2Dir[agentIndex].dir[index].lock =
                    MDR2DirLockEnum::mdr2DirLock;
                timer->start(usec);
                lockIndex = index;

                *session = getSessionHandle(&mdrv2Dir[agentIndex]);
                mdrv2Dir[agentIndex].dir[index].lockHandle = *session;

                ret = true;
            }
            break;
        case MDR2SMBIOSStatusEnum::mdr2Init:
            if (flag)
            {
                mdrv2Dir[agentIndex].dir[index].stage =
                    MDR2SMBIOSStatusEnum::mdr2Updating;
                mdrv2Dir[agentIndex].dir[index].lock =
                    MDR2DirLockEnum::mdr2DirUnlock;
                timer->start(usec);
                lockIndex = index;

                *session = getSessionHandle(&mdrv2Dir[agentIndex]);
                mdrv2Dir[agentIndex].dir[index].lockHandle = *session;
                ret = true;
            }
            break;

        case MDR2SMBIOSStatusEnum::mdr2Updated:
        case MDR2SMBIOSStatusEnum::mdr2Loaded:
            if (mdrv2Dir[agentIndex].dir[index].lock !=
                MDR2DirLockEnum::mdr2DirLock)
            {
                if (flag)
                {
                    mdrv2Dir[agentIndex].dir[index].stage =
                        MDR2SMBIOSStatusEnum::mdr2Updating;
                    mdrv2Dir[agentIndex].dir[index].lock =
                        MDR2DirLockEnum::mdr2DirUnlock;
                }
                else
                {
                    mdrv2Dir[agentIndex].dir[index].lock =
                        MDR2DirLockEnum::mdr2DirLock;
                }

                timer->start(usec);
                lockIndex = index;

                *session = getSessionHandle(&mdrv2Dir[agentIndex]);
                mdrv2Dir[agentIndex].dir[index].lockHandle = *session;
                ret = true;
            }
            break;

        default:
            break;
    }
    return ret;
}

void MDRV2::timeoutHandler()
{
    smbiosUnlock(currentAgentIndex, lockIndex);
    mdrv2->area.reset(nullptr);
}

/** @brief implements mdr2 lock data command
 *  @param agentId
 *  @param dataInfo
 *  @param timeout
 *
 *  @returns IPMI completion code plus response data
 *  - mdr2Version
 *  - session
 *  - dataLength
 *  - xferAddress
 *  - xferLength
 */
ipmi::RspType<uint8_t,  // mdr2Version
              uint16_t, // session
              uint32_t, // dataLength
              uint32_t, // xferAddress
              uint32_t  // xferLength
              >
    mdr2LockData(uint16_t agentId, std::array<uint8_t, dataInfoSize> dataInfo,
                 uint16_t timeout)
{
    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    int idIndex = 0;
    if (mdrv2->mdrv2Dir[agentIndex].overrideFlag ||
        mdrv2->mdrv2Dir[agentIndex].mdrv2Interface == nullptr ||
        mdrv2->mdrv2Dir[agentIndex].mdrv2Path == nullptr)
    {
        std::vector<uint8_t> arrayDataInfo;
        arrayDataInfo.resize(dataInfo.size());
        std::copy(dataInfo.data(), dataInfo.data() + dataInfo.size(),
                  arrayDataInfo.data());
        int index = 0;
        for (; index < mdrv2->mdrv2Dir[agentIndex].dirEntries; index++)
        {
            size_t info = 0;
            for (; info < arrayDataInfo.size(); info++)
            {
                if (arrayDataInfo[info] != mdrv2->mdrv2Dir[agentIndex]
                                               .dir[index]
                                               .common.id.dataInfo[info])
                {
                    break;
                }
            }
            if (info == arrayDataInfo.size())
            {
                idIndex = index;
                break;
            }
        }
        if ((static_cast<int>(mdrv2->mdrv2Dir[agentIndex].dirEntries) == index))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid Data ID",
                phosphor::logging::entry("IDINDEX=%x", idIndex));
            return ipmi::responseParmOutOfRange();
        }
    }
    else
    {
        std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
        std::string service =
            ipmi::getService(*bus, mdrv2->mdrv2Dir[agentIndex].mdrv2Interface,
                             mdrv2->mdrv2Dir[agentIndex].mdrv2Path);

        idIndex = mdrv2->findDataId(dataInfo.data(), dataInfo.size(), service);

        if ((idIndex < 0) || (idIndex >= maxDirEntries))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid Data ID",
                phosphor::logging::entry("IDINDEX=%x", idIndex));
            return ipmi::responseParmOutOfRange();
        }
    }

    uint16_t session = 0;
    if (!mdrv2->smbiosTryLock(agentIndex, 0, idIndex, &session, timeout))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Lock Data failed - cannot lock idIndex");
        return ipmi::responseCommandNotAvailable();
    }

    uint32_t dataLength = mdrv2->mdrv2Dir[agentIndex].dir[idIndex].common.size;
    uint32_t xferAddress = mdrv2->mdrv2Dir[agentIndex].dir[idIndex].xferBuff;
    uint32_t xferLength = mdrv2->mdrv2Dir[agentIndex].dir[idIndex].xferSize;

    return ipmi::responseSuccess(mdr2Version, session, dataLength, xferAddress,
                                 xferLength);
}

/** @brief implements mdr2 unlock data command
 *  @param agentId
 *  @param lockHandle
 *
 *  @returns IPMI completion code
 */
ipmi::RspType<> mdr2UnlockData(uint16_t agentId, uint16_t lockHandle)
{
    phosphor::logging::log<phosphor::logging::level::ERR>("unlock data");

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    int idIndex = mdrv2->findLockHandle(agentIndex, lockHandle);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return ipmi::responseParmOutOfRange();
    }

    if (!mdrv2->smbiosUnlock(agentIndex, idIndex))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unlock Data failed - cannot unlock idIndex");
        return ipmi::responseCommandNotAvailable();
    }

    return ipmi::responseSuccess();
}

/**
@brief This command is executed after POST BIOS to get the session info.

@param - agentId, dataInfo, dataLength, xferAddress, xferLength, timeout.

@return xferStartAck and session on success.
**/
ipmi::RspType<uint8_t, uint16_t> cmd_mdr2_data_start(
    uint16_t agentId, std::array<uint8_t, 16> dataInfo, uint32_t dataLength,
    uint32_t xferAddress, uint32_t xferLength, uint16_t timeout)
{
    uint16_t session = 0;
    std::string service;

    if (dataLength > smbiosTableStorageSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Requested data length is out of SMBIOS Table storage size.");
        return ipmi::responseParmOutOfRange();
    }
    if ((xferLength + xferAddress) > mdriiSMSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid data address and size");
        return ipmi::responseParmOutOfRange();
    }

    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    int idIndex = 0;
    if (mdrv2->mdrv2Dir[agentIndex].overrideFlag ||
        mdrv2->mdrv2Dir[agentIndex].mdrv2Interface == nullptr ||
        mdrv2->mdrv2Dir[agentIndex].mdrv2Path == nullptr)
    {
        std::filesystem::path filepath(mdrv2->mdrv2Dir[agentIndex].fileName);
        if (std::filesystem::exists(filepath))
        {
            std::cout << "removing file -" << filepath.c_str() << std::endl;
            std::filesystem::remove_all(filepath);
        }
        std::vector<uint8_t> arrayDataInfo;
        arrayDataInfo.resize(dataInfo.size());
        std::copy(dataInfo.data(), dataInfo.data() + dataInfo.size(),
                  arrayDataInfo.data());
        int index = 0;
        for (; index < mdrv2->mdrv2Dir[agentIndex].dirEntries; index++)
        {
            size_t info = 0;
            for (; info < arrayDataInfo.size(); info++)
            {
                if (arrayDataInfo[info] != mdrv2->mdrv2Dir[agentIndex]
                                               .dir[index]
                                               .common.id.dataInfo[info])
                {
                    break;
                }
            }
            if (info == arrayDataInfo.size())
            {
                idIndex = index;
                break;
            }
        }
        if (static_cast<int>(mdrv2->mdrv2Dir[agentIndex].dirEntries) == index)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid1 Data ID",
                phosphor::logging::entry("IDINDEX=%x", idIndex));
            return ipmi::responseParmOutOfRange();
        }
    }
    else
    {
        std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
        service = ipmi::getService(*bus,
                                   mdrv2->mdrv2Dir[agentIndex].mdrv2Interface,
                                   mdrv2->mdrv2Dir[agentIndex].mdrv2Path);
        idIndex = mdrv2->findDataId(dataInfo.data(), dataInfo.size(), service);

        if ((idIndex < 0) || (idIndex >= maxDirEntries))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid Data ID",
                phosphor::logging::entry("IDINDEX=%x", idIndex));
            return ipmi::responseParmOutOfRange();
        }
    }

    if (mdrv2->smbiosTryLock(agentIndex, 1, idIndex, &session, timeout))
    {
        try
        {
            mdrv2->area =
                std::make_unique<SharedMemoryArea>(xferAddress, xferLength);
        }
        catch (const std::system_error& e)
        {
            mdrv2->smbiosUnlock(agentIndex, idIndex);
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unable to access share memory",
                phosphor::logging::entry("ERROR=%s", e.what()));
            return ipmi::responseUnspecifiedError();
        }
        mdrv2->mdrv2Dir[agentIndex].dir[idIndex].common.size = dataLength;
        mdrv2->mdrv2Dir[agentIndex].dir[idIndex].lockHandle = session;
        if (!(mdrv2->mdrv2Dir[agentIndex].overrideFlag ||
              mdrv2->mdrv2Dir[agentIndex].mdrv2Interface == nullptr ||
              mdrv2->mdrv2Dir[agentIndex].mdrv2Path == nullptr))
        {
            if (-1 == mdrv2->syncDirCommonData(
                          agentIndex, idIndex,
                          mdrv2->mdrv2Dir[agentIndex].dir[idIndex].common.size,
                          service))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Unable to sync data to service");
                return ipmi::responseResponseError();
            }
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Canot lock smbios");
        return ipmi::responseUnspecifiedError();
    }

    static constexpr uint8_t xferStartAck = 1;

    return ipmi::responseSuccess(xferStartAck, session);
}

/**
@brief This command is executed to close the session.

@param - agentId, lockHandle.

@return completion code on success.
**/
ipmi::RspType<> cmd_mdr2_data_done(uint16_t agentId, uint16_t lockHandle)
{
    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    int idIndex = mdrv2->findLockHandle(agentIndex,lockHandle);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return ipmi::responseParmOutOfRange();
    }

    if (!mdrv2->smbiosUnlock(agentIndex, idIndex))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Send data done failed - cannot unlock idIndex");
        return ipmi::responseDestinationUnavailable();
    }

    mdrv2->area.reset(nullptr);
    MDRSMBIOSHeader mdr2Smbios;
    mdr2Smbios.mdrType = mdrTypeII;
    mdr2Smbios.dirVer = mdrv2->mdrv2Dir[agentIndex].dir[0].common.dataVersion;
    mdr2Smbios.timestamp = mdrv2->mdrv2Dir[agentIndex].dir[0].common.timestamp;
    mdr2Smbios.dataSize = mdrv2->mdrv2Dir[agentIndex].dir[0].common.size;

    if (access(reinterpret_cast<char*>(mdrv2->mdrv2Dir[agentIndex].datadirPath),
               0) == -1)
    {
        // create the crashdump/output directory if it doesn't exist
        std::error_code ec;
        std::filesystem::path dumpDir = mdrv2->mdrv2Dir[agentIndex].datadirPath;
        if (!(std::filesystem::create_directories(dumpDir, ec)))
        {
            if (ec.value() != 0)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "failed to create folder",
                    phosphor::logging::entry("crashdumpDir=%s",
                                             dumpDir.c_str()));
            }
        }
    }
    if (!mdrv2->storeDatatoFlash(
            agentIndex, &mdr2Smbios,
            mdrv2->mdrv2Dir[agentIndex].dir[mdrv2DirIndex].dataStorage))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "MDR2 Store data to flash failed");
        return ipmi::responseDestinationUnavailable();
    }
    bool status = false;
    if (!(mdrv2->mdrv2Dir[agentIndex].overrideFlag ||
          mdrv2->mdrv2Dir[agentIndex].mdrv2Interface == nullptr ||
          mdrv2->mdrv2Dir[agentIndex].mdrv2Path == nullptr))
    {
        std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
        std::string service =
            ipmi::getService(*bus, mdrv2->mdrv2Dir[agentIndex].mdrv2Interface,
                             mdrv2->mdrv2Dir[agentIndex].mdrv2Path);
        sdbusplus::message_t method = bus->new_method_call(
            service.c_str(), mdrv2->mdrv2Dir[agentIndex].mdrv2Path,
            mdrv2->mdrv2Dir[agentIndex].mdrv2Interface, "AgentSynchronizeData");

        try
        {
            sdbusplus::message_t reply = bus->call(method);
            reply.read(status);
        }
        catch (const sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error Sync data with service",
                phosphor::logging::entry("ERROR=%s", e.what()),
                phosphor::logging::entry("SERVICE=%s", service.c_str()),
                phosphor::logging::entry(
                    "PATH=%s", mdrv2->mdrv2Dir[agentIndex].mdrv2Path));
            return ipmi::responseResponseError();
        }

        if (!status)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Sync data with service failure");
            return ipmi::responseUnspecifiedError();
        }
    }

    return ipmi::responseSuccess();
}

static void register_netfn_smbiosmdrv2_functions(void)
{
    // MDR V2 Command
    // <Get MDRII Status Command>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnApp,
                          ipmi::intel::app::cmdMdrIIAgentStatus,
                          ipmi::Privilege::Operator, mdr2AgentStatus);

    // <Get MDRII Directory Command>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnApp,
                          ipmi::intel::app::cmdMdrIIGetDir,
                          ipmi::Privilege::Operator, mdr2GetDir);

    // <Send MDRII Directory Command>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnApp,
                          ipmi::intel::app::cmdMdrIISendDir,
                          ipmi::Privilege::Operator, mdr2SendDir);

    // <Get MDRII Data Info Command>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnApp,
                          ipmi::intel::app::cmdMdrIIGetDataInfo,
                          ipmi::Privilege::Operator, mdr2GetDataInfo);

    // <Send MDRII Info Offer>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnApp,
                          ipmi::intel::app::cmdMdrIISendDataInfoOffer,
                          ipmi::Privilege::Operator, mdr2DataInfoOffer);

    // <Send MDRII Data Info>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnApp,
                          ipmi::intel::app::cmdMdrIISendDataInfo,
                          ipmi::Privilege::Operator, mdr2SendDataInfo);

    // <Get MDRII Data Block Command>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnApp,
                          ipmi::intel::app::cmdMdrIIGetDataBlock,
                          ipmi::Privilege::Operator, mdr2GetDataBlock);

    // <Send MDRII Data Block>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnApp,
                          ipmi::intel::app::cmdMdrIISendDataBlock,
                          ipmi::Privilege::Operator, mdr2SendDataBlock);

    // <Lock MDRII Data Command>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnApp,
                          ipmi::intel::app::cmdMdrIILockData,
                          ipmi::Privilege::Operator, mdr2LockData);

    // <Unlock MDRII Data Command>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnApp,
                          ipmi::intel::app::cmdMdrIIUnlockData,
                          ipmi::Privilege::Operator, mdr2UnlockData);

    // <Send MDRII Data Start>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnApp,
                          ipmi::intel::app::cmdMdrIIDataStart,
                          ipmi::Privilege::Operator, cmd_mdr2_data_start);

    // <Send MDRII Data Done>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnApp,
                          ipmi::intel::app::cmdMdrIIDataDone,
                          ipmi::Privilege::Operator, cmd_mdr2_data_done);
}

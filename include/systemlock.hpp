#include <ipmi-systemlock.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <algorithm>
#include <array>

static constexpr const char* systemLockIntf =
    "xyz.openbmc_project.Control.Security.SystemLock";
static constexpr const char* systemLockObj =
    "/xyz/openbmc_project/control/systemlock";

/** @brief get the systemlock property value **/
inline bool getDbusSysLockProperty()
{
    bool sysLock{};
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        auto service = ipmi::getService(*dbus, systemLockIntf, systemLockObj);
        ipmi::Value v = ipmi::getDbusProperty(*dbus, service, systemLockObj,
                                              systemLockIntf, "SystemLocked");
        sysLock = std::get<bool>(v);
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get syslock property");
    }
    catch (const std::exception&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get dbus property of syslock");
    }
    return sysLock;
}
namespace ipmi
{
/** @brief filter the set commands from ipmi-set-allowlist configuartion file **/
ipmi::Cc filterSetCmdMessage(ipmi::message::Request::ptr request)
{
    auto channelMask = static_cast<unsigned short>(1 << request->ctx->channel);
    bool setAllowlisted = std::binary_search(
        setallowlist.cbegin(), setallowlist.cend(),
        std::make_tuple(request->ctx->netFn, request->ctx->cmd, channelMask),
        [](const netfncmd_tuple& first, const netfncmd_tuple& value) {
            return (std::get<2>(first) & std::get<2>(value))
                       ? first < std::make_tuple(std::get<0>(value),
                                                 std::get<1>(value),
                                                 std::get<2>(first))
                       : first < value;
        });
    if (request->ctx->channel != ipmi::channelSystemIface)
    {
        if (setAllowlisted)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Channel/NetFn/Cmd not Allowlisted");
            return ipmi::ccCommandDisabled;
        }
    }
    return ipmi::ccSuccess;
}
} // namespace ipmi

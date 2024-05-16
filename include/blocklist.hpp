
#include <ipmi-blocklist.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>

#include <algorithm>
#include <array>
namespace ipmi
{

static bool Blocklisted = false;

bool compare_tuples(const netfncmds_tuple& first, const netfncmds_tuple& value)
{
    // Compare the first and value tuples
    if (std::get<0>(first) == std::get<0>(value))
    {
        return std::get<1>(first) < std::get<1>(value);
    }
    return std::get<0>(first) < std::get<0>(value);
}

/** @brief If user need to block the commands from system interface in blocklist
 * configuration file  **/
ipmi::Cc filterblocklistcmdMessage(ipmi::message::Request::ptr request)
{
    Blocklisted = std::binary_search(
        blocklist.cbegin(), blocklist.cend(),
        std::make_tuple(request->ctx->netFn, request->ctx->cmd),
        compare_tuples);

    if (Blocklisted)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Channel/NetFn/Cmd not Allowlisted");
        return ipmi::ccCommandDisabled;
    }
    return ipmi::ccSuccess;
}

} // namespace ipmi

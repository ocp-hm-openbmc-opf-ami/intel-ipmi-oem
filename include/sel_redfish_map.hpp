/*
// Copyright (c) 2026 American Megatrends International LLC (AMI)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#pragma once

#include <cstdint>
#include <string>
#include <utility>

namespace intel_oem::ipmi::sel
{

/**
 * @brief JSON-driven IPMI -> Redfish Message mapper.
 *
 * Loads a mapping JSON file once on first use; for each Add-SEL request
 * looks up (sensorType, eventType, offset, assert) and renders a
 * "AMI.1.0.<MessageId>,arg1,arg2,..." string.
 *
 * If no JSON is installed or no entry matches, format() returns an empty
 * string so the caller can fall back to legacy behavior unchanged.
 */
class SelRedfishMap
{
  public:
    static SelRedfishMap& instance();

    /**
     * @brief Build the Redfish-style Message string for a SEL event.
     *
     * @param generatorID  IPMI generator ID (16-bit).
     * @param sensorType   IPMI sensor type code.
     * @param sensorNum    IPMI sensor number.
     * @param eventType    IPMI event/reading type code (0x01 threshold,
     *                     0x6F sensor-specific, 0x03..0x0C generic discrete).
     * @param eventData1   IPMI event data 1 (offset is bits [3:0]).
     * @param eventData2   IPMI event data 2 (raw byte).
     * @param eventData3   IPMI event data 3 (raw byte).
     * @param sensorPath   D-Bus object path of the sensor (basename used as
     *                     SensorName in args).
     *
     * @return "AMI.1.0.<Id>,arg1,arg2,..." on a successful lookup; empty
     *         string when no row matches and no fallback applies.
     */
    std::string format(uint16_t generatorID, uint8_t sensorType,
                       uint8_t sensorNum, uint8_t eventType, uint8_t eventData1,
                       uint8_t eventData2, uint8_t eventData3,
                       const std::string& sensorPath) const;

    /**
     * @brief Split a "AMI.1.0.<Id>,arg1,arg2,..." string into the Id and
     *        the comma-joined args. If no comma is present, args is empty.
     */
    static std::pair<std::string, std::string> splitIdArgs(
        const std::string& message);

  private:
    SelRedfishMap();
    ~SelRedfishMap();
    SelRedfishMap(const SelRedfishMap&) = delete;
    SelRedfishMap& operator=(const SelRedfishMap&) = delete;

    struct Impl;
    Impl* impl;
};

} // namespace intel_oem::ipmi::sel

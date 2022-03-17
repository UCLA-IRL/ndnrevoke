#include "rk-configuration.hpp"

#include <ndn-cxx/util/io.hpp>

#include <boost/filesystem.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace ndnrevoke {
namespace rk {

const std::string CONFIG_RK_PREFIX = "rk-prefix";
const std::string CONFIG_RECORD_FRESHNESS_PERIOD = "record-freshness-period";
const std::string CONFIG_NACK_FRESHNESS_PERIOD = "nack-freshness-period";
const std::string CONFIG_RECORD_ZONES = "record-zones";
const std::string CONFIG_RECORD_ZONE_PREFIX = "record-zone-prefix";

void
RkConfig::load(const std::string& fileName)
{
  JsonSection configJson;
  try {
    boost::property_tree::read_json(fileName, configJson);
  }
  catch (const std::exception& error) {
    NDN_THROW(std::runtime_error("Failed to parse configuration file " + fileName + ", " + error.what()));
  }
  if (configJson.begin() == configJson.end()) {
    NDN_THROW(std::runtime_error("No JSON configuration found in file: " + fileName));
  }


 // RK prefix
  rkPrefix = Name(configJson.get(CONFIG_RK_PREFIX, ""));
  if (rkPrefix.empty()) {
    NDN_THROW(std::runtime_error("Cannot parse rk-prefix from the config file"));
  }
  recordFreshnessPeriod = time::seconds(configJson.get(CONFIG_RECORD_FRESHNESS_PERIOD, 86400));
  // Nack Freshness Period
  nackFreshnessPeriod = time::seconds(configJson.get(CONFIG_NACK_FRESHNESS_PERIOD, 86400));
  // Record Zones
  recordZones.clear();
  auto recordZonePrefixJson = configJson.get_child_optional(CONFIG_RECORD_ZONES);
  if (recordZonePrefixJson) {
    for (const auto& item : *recordZonePrefixJson) {
      auto recordZonePrefix = item.second.get(CONFIG_RECORD_ZONE_PREFIX, "");
      if (recordZonePrefix == "") {
        NDN_THROW(std::runtime_error("recordZonePrefix cannot be empty."));
      }
      recordZones.push_back(Name(recordZonePrefix));
    }
  }
  else {
    NDN_THROW(std::runtime_error("No recordZone configured."));
  }

  // in fact, we also need configure trust policies, but will do later
}

} // namespace rk
} // namespace ndnrevoke

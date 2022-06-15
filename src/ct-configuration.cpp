#include "ct-configuration.hpp"

#include <ndn-cxx/util/io.hpp>

#include <boost/filesystem.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace ndnrevoke::ct {

const std::string CONFIG_CT_PREFIX = "ct-prefix";
const std::string CONFIG_NACK_FRESHNESS_PERIOD = "nack-freshness-period";
const std::string CONFIG_RECORD_ZONES = "record-zones";
const std::string CONFIG_RECORD_ZONE_PREFIX = "record-zone-prefix";
const std::string CONFIG_TRUST_SCHEMA = "trust-schema";

void
CtConfig::load(const std::string& fileName)
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


  // Ct prefix
  ctPrefix = Name(configJson.get(CONFIG_CT_PREFIX, ""));
  if (ctPrefix.empty()) {
    NDN_THROW(std::runtime_error("Cannot parse ct-prefix from the config file"));
  }
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

  schemaFile = configJson.get(CONFIG_TRUST_SCHEMA, "");
  if (schemaFile.empty()) {
    NDN_THROW(std::runtime_error("Cannot parse trust schema from the config file"));
  }
}

} // namespace ndnrevoke::ct

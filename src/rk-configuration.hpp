#ifndef NDNREVOKE_RK_CONFIGURATION_HPP
#define NDNREVOKE_RK_CONFIGURATION_HPP

#include "revocation-common.hpp"

namespace ndnrevoke {
namespace rk {

/**
 * @brief RK's configuration on NDNREVOKE.
 *
 * The format of RK configuration in JSON
 * {
 *  "rk-prefix": "",
 *  "record-freshness-period": "", (in seconds)
 *  "nack-freshness-period": "", (in seconds)
 *  "record-zones":
 *  [
 *    {"record-zone-prefix": ""},
 *    {"record-zone-prefix": ""}
 *  ]
 * }
 */
class RkConfig
{
public:
  /**
   * @brief Load RK configuration from the file.
   * @throw std::runtime_error when config file cannot be correctly parsed.
   */
  void
  load(const std::string& fileName);

public:
  Name rkPrefix;
  ndn::time::milliseconds recordFreshnessPeriod;
  ndn::time::milliseconds nackFreshnessPeriod;
  // operator should list the namespace(s) that this RK is responsible of.
  // RK won't do look up for records that are that belong to any of the record Zone.
  // no protocol side impact, purely for filtering RK side unnecessary record look up.
  std::vector<Name> recordZones;
};

} // namespace rk
} // namespace ndnrevoke

#endif // NDNREVOKE_RK_CONFIGURATION_HPP

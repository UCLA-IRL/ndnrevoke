#ifndef NDNREVOKE_CT_CONFIGURATION_HPP
#define NDNREVOKE_CT_CONFIGURATION_HPP

#include "revocation-common.hpp"

namespace ndnrevoke::ct {

/**
 * @brief CT's configuration on NDNREVOKE.
 *
 * The format of CT configuration in JSON
 * {
 *  "ct-prefix": "",
 *  "nack-freshness-period": "", (in seconds)
 *  "record-zones":
 *  [
 *    {"record-zone-prefix": ""},
 *    {"record-zone-prefix": ""}
 *  ]
 * }
 */
class CtConfig
{
public:
  /**
   * @brief Load Ct configuration from the file.
   * @throw std::runtime_error when config file cannot be correctly parsed.
   */
  void
  load(const std::string& fileName);

public:
  Name ctPrefix;
  ndn::time::milliseconds nackFreshnessPeriod;
  // operator should list the namespace(s) that this Ct is responsible of.
  // Ct won't do look up for records that are that belong to any of the record Zone.
  // no protocol side impact, purely for filtering Ct side unnecessary record look up.
  std::vector<Name> recordZones;
};

} // namespace ndnrevoke::ct

#endif // NDNREVOKE_CT_CONFIGURATION_HPP

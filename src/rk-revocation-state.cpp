#include "rk-revocation-state.hpp"

#include <ndn-cxx/util/indented-stream.hpp>

#include <boost/property_tree/json_parser.hpp>

namespace ndnrevoke {

std::string statusToString(RevocationStatus status)
{
  switch (status) {
  case RevocationStatus::NOTINITIALIZED:
    return "NOT INITIALIZED";
  case RevocationStatus::VALID_CERTIFICATE:
    return "VALID CERTIFICATE";
  case RevocationStatus::REVOKED_CERTIFICATE:
    return "REVOKED CERTIFICATE";
  default:
    return "Unrecognized status";
  }
}

RevocationStatus
statusFromBlock(const Block& block)
{
  auto status_int = readNonNegativeInteger(block);
  if (status_int > 2)
      NDN_THROW(std::runtime_error("Unrecognized Status"));
  return static_cast<RevocationStatus>(status_int);
}

namespace rk {

std::ostream&
operator<<(std::ostream& os, const RevocationState& state)
{
  os << "State's Corresponding Certificate Name: " << state.certName << "\n";
  os << "State's Record Keeper name: " << state.rkPrefix << "\n";
  os << "State's RevocationStatus: " << statusToString(state.status) << "\n";
  os << "State's (Revocation) ReasonCode: " << static_cast<uint64_t>(state.reasonCode) << "\n";
  if (!state.publisherId.empty()) {
    os << "State's Corresponding Publisher ID: " << state.publisherId << "\n";
  }
  if (!state.publicKeyHash.empty()) {
    os << "State's Corresponding Certificate Public Key Hash: "
       << ndn::toHex(state.publicKeyHash.data(), state.publicKeyHash.size()) << "\n";
  }
  return os;
}

} // namespace rk
} // namespace ndnrevoke

#include "rk-revocation-state.hpp"
#include "state.hpp"

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

std::shared_ptr<RevocationState>
makeRevocationState(record::Record& record)
{
  auto certName = record.getName();
  certName.set(record::Record::REVOKE_OFFSET, Name::Component("KEY"));
  certName.erase(record::Record::PUBLISHER_OFFSET);
  ndn::KeyChain dummyKeyChain;
  state::State state(certName, dummyKeyChain);
  state.getRecord(record);
  
  auto revocationState = std::make_shared<RevocationState>();
  revocationState->certName = certName;
  revocationState->publicKeyHash = state.m_publicKeyHash;
  revocationState->record = record;
  if (state.m_revocationTimestamp.has_value()) {
    revocationState->revocationTimestamp = state.m_revocationTimestamp.value();
  }
  if (state.m_revocationReason.has_value()) {
    revocationState->reasonCode = state.m_revocationReason.value();
  }
  if (state.m_publisher.has_value()) {
    revocationState->publisherId = state.m_publisher.value();
  }

  if (state.m_revocationReason.has_value() && state.m_revocationTimestamp.has_value())
  {
    revocationState->status = RevocationStatus::REVOKED_CERTIFICATE;
  }
  return revocationState;
}

std::shared_ptr<RevocationState>
makeRevocationState(Certificate& cert)
{
  ndn::KeyChain dummyKeyChain;
  state::State state(cert, dummyKeyChain);
  
  auto revocationState = std::make_shared<RevocationState>();
  revocationState->certName = cert.getName();
  revocationState->publicKeyHash = state.m_publicKeyHash;
  revocationState->status = RevocationStatus::VALID_CERTIFICATE;
  return revocationState;
}

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

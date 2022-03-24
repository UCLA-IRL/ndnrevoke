#include "ct-certificate-state.hpp"
#include "state.hpp"

#include <ndn-cxx/util/indented-stream.hpp>

#include <boost/property_tree/json_parser.hpp>

namespace ndnrevoke {

std::string statusToString(CertificateStatus status)
{
  switch (status) {
    case CertificateStatus::NOTINITIALIZED:
      return "NOT INITIALIZED";
    case CertificateStatus::VALID_CERTIFICATE:
      return "VALID CERTIFICATE";
    case CertificateStatus::REVOKED_CERTIFICATE:
      return "REVOKED CERTIFICATE";
    default:
      return "Unrecognized status";
  }
}

CertificateStatus
statusFromBlock(const Block& block)
{
  auto status_int = readNonNegativeInteger(block);
  if (status_int > 2)
      NDN_THROW(std::runtime_error("Unrecognized Status"));
  return static_cast<CertificateStatus>(status_int);
}

namespace ct {

void CertificateState::updateCertificateState(record::Record& record)
{
  auto certName = record::Record::getCertificateName(record.getName());
  ndn::KeyChain dummyKeyChain;
  state::State state(certName, dummyKeyChain);
  state.getRecord(record);

  this->cert.setName(certName);
  this->publicKeyHash = state.m_publicKeyHash;
  this->record = record;
  if (state.m_revocationTimestamp.has_value()) {
      this->revocationTimestamp = state.m_revocationTimestamp.value();
  }
  if (state.m_revocationReason.has_value()) {
      this->reasonCode = state.m_revocationReason.value();
  }
  if (state.m_publisher.has_value()) {
      this->publisherId = state.m_publisher.value();
  }
  if (state.m_revocationReason.has_value() && state.m_revocationTimestamp.has_value())
  {
      this->status = CertificateStatus::REVOKED_CERTIFICATE;
  }
}

std::shared_ptr<CertificateState>
makeCertificateState(Certificate& cert)
{
  ndn::KeyChain dummyKeyChain;
  state::State state(cert, dummyKeyChain);
  
  auto certState = std::make_shared<CertificateState>();
  certState->cert = cert;
  certState->publicKeyHash = state.m_publicKeyHash;
  certState->status = CertificateStatus::VALID_CERTIFICATE;
  return certState;
}

std::ostream&
operator<<(std::ostream& os, const CertificateState& state)
{
  os << "State's Corresponding Certificate Name: " << state.cert.getName() << "\n";
  os << "State's Certificate Transparency name: " << state.ctPrefix << "\n";
  os << "State's CertificateStatus: " << statusToString(state.status) << "\n";
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

} // namespace ct
} // namespace ndnrevoke

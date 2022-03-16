#ifndef NDNREVOKE_REVOCATION_STATE_HPP
#define NDNREVOKE_REVOCATION_STATE_HPP

#include <optional>
#include "revocation-common.hpp"
#include "record.hpp"
#include "nack.hpp"
#include <ndn-cxx/security/key-chain.hpp>

namespace ndnrevoke {
namespace state {

class State : boost::noncopyable
{
public:
  explicit
  State(Certificate& certData, ndn::KeyChain& keyChain);

  explicit
  State(Name& certName, ndn::KeyChain& keyChain);

  std::shared_ptr<record::Record>
  genIssuerRecord(const Name& signingKeyName, ndn::time::milliseconds freshnessPeriod = 100_h);

  std::shared_ptr<record::Record>
  genOwnerRecord(const Name& signingKeyName, ndn::time::milliseconds freshnessPeriod = 100_h);

  void
  getRecord(const record::Record& record);

  std::shared_ptr<nack::Nack>
  genNack(const Name& signingKeyName, ndn::time::milliseconds freshnessPeriod = 10_h);

  void
  getNack(const nack::Nack& nack);

  // util
  bool
  isRevoked()
  {
    if (m_revocationReason.has_value() && 
        m_revocationReason.value() != tlv::ReasonCode::INVALID)
    {
      return true;
    }
    return false;
  }
  
  void
  setCertificateData(Certificate& certData)
  {
    m_certData = certData;
    auto buf = Sha256::computeDigest(m_certData.value().getPublicKey());
    m_publicKeyHash.assign(buf->begin(), buf->end());
  }

  void
  setPublisher(Name::Component publisher)
  {
    m_publisher = publisher;
  }

  void
  setRevocationReason(tlv::ReasonCode reasonCode)
  {
    m_revocationReason = reasonCode;
  }

  void
  setNackCode(tlv::NackCode nackCode)
  {
    m_nackCode = nackCode;
  }

public:
  Name m_certName;
  std::vector<uint8_t> m_publicKeyHash;
  
  // helper
  optional<Certificate> m_certData;

  // if revoked
  optional<uint64_t> m_revocationTimestamp;
  optional<tlv::ReasonCode> m_revocationReason;
  optional<Name::Component> m_publisher;
  // if not revoked
  optional<tlv::NackCode> m_nackCode;
private:
  ndn::KeyChain& m_keyChain;
};

} // namespace state
} // namespace ndnrevoke

#endif // NDNREVOKE_REVOCATION_STATE_HPP

#ifndef NDNREVOKE_REVOCATION_STATE_HPP
#define NDNREVOKE_REVOCATION_STATE_HPP

#include "revocation-common.hpp"
#include "record.hpp"
#include <ndn-cxx/security/key-chain.hpp>

namespace ndnrevoke {
namespace state {

class State : boost::noncopyable
{
public:
  explicit
  State(Certificate& certToRevoke, ndn::KeyChain& keyChain, tlv::ReasonCode reasonCode = tlv::ReasonCode::UNSPECIFIED);

  std::shared_ptr<record::Record>
  genIssuerRecord(const Name& signingKeyName);

  std::shared_ptr<record::Record>
  genOwnerRecord(const Name& signingKeyName);

  void
  getRecord(const record::Record& record);
  
public:
  Certificate m_certToRevoke;
  std::vector<uint8_t> m_publicKeyHash;
  uint64_t m_revocationTimestamp;
  tlv::ReasonCode m_revocationReason;
  Name::Component m_publisher;
private:
  ndn::KeyChain& m_keyChain;
};

} // namespace state
} // namespace ndnrevoke

#endif // NDNREVOKE_REVOCATION_STATE_HPP

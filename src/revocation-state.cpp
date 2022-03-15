#include "revocation-state.hpp"
#include "record-encoder.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndnrevoke {
namespace state {

State::State(Certificate& certToRevoke, ndn::KeyChain& keyChain, tlv::ReasonCode reasonCode)
  : m_certToRevoke(certToRevoke)
  , m_keyChain(keyChain)
  , m_revocationReason(reasonCode)
{
  auto buf = Sha256::computeDigest(m_certToRevoke.getPublicKey());
  m_publicKeyHash.assign(buf->begin(), buf->end());
}

std::shared_ptr<record::Record>
State::genIssuerRecord(const Name& signingKeyName)
{
  auto recordName = m_certToRevoke.getName();
  recordName.set(m_certToRevoke.getIdentity().size(), Name::Component("REVOKE"));
  m_publisher = Name::Component(m_certToRevoke.getIssuerId());
  recordName.append(m_publisher);
  
  std::shared_ptr<record::Record> record = std::make_shared<record::Record>();
  record->setName(recordName);
  record->setFreshnessPeriod(10_h);
  record->setContent(recordtlv::encodeRecordContent(m_publicKeyHash, m_revocationReason));
  m_keyChain.sign(*record, signingByKey(signingKeyName));
  return record;
}

std::shared_ptr<record::Record>
State::genOwnerRecord(const Name& signingKeyName)
{
  auto recordName = m_certToRevoke.getName();
  recordName.set(m_certToRevoke.getIdentity().size(), Name::Component("REVOKE"));
  m_publisher = Name::Component("self");
  recordName.append(m_publisher);
  
  std::shared_ptr<record::Record> record = std::make_shared<record::Record>();
  record->setName(recordName);
  record->setFreshnessPeriod(10_h);
  record->setContent(recordtlv::encodeRecordContent(m_publicKeyHash, m_revocationReason));
  m_keyChain.sign(*record, signingByKey(signingKeyName));
  return record;
}

void
State::getRecord(const record::Record& record)
{
  recordtlv::decodeRecordContent(record.getContent(), *this);
}

} // namespace record
} // namespace ndnrevoke

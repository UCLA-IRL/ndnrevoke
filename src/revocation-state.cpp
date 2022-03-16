#include "revocation-state.hpp"
#include "record-encoder.hpp"
#include "nack.hpp"
#include "nack-encoder.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndnrevoke {
namespace state {

State::State(Certificate& certData, ndn::KeyChain& keyChain)
  : m_certData(certData)
  , m_keyChain(keyChain)
{
  m_certName = m_certData.value().getName();
  auto buf = Sha256::computeDigest(m_certData.value().getPublicKey());
  m_publicKeyHash.assign(buf->begin(), buf->end());
}

// keychain may not be useful
State::State(Name& certName, ndn::KeyChain& keyChain)
  : m_certName(certName)
  , m_keyChain(keyChain)
{
}

std::shared_ptr<record::Record>
State::genIssuerRecord(const Name& signingKeyName)
{
  auto recordName = m_certName;
  recordName.set(m_certData.value().getIdentity().size(), Name::Component("REVOKE"));
  m_publisher = Name::Component(m_certData.value().getIssuerId());
  recordName.append(m_publisher.value());
  
  std::shared_ptr<record::Record> record = std::make_shared<record::Record>();
  record->setName(recordName);
  record->setFreshnessPeriod(10_h);

  BOOST_ASSERT(m_revocationReason.has_value());
  record->setContent(recordtlv::encodeRecordContent(m_publicKeyHash, m_revocationReason.value()));
  m_keyChain.sign(*record, signingByKey(signingKeyName));
  return record;
}

std::shared_ptr<record::Record>
State::genOwnerRecord(const Name& signingKeyName)
{
  auto recordName = m_certName;
  recordName.set(m_certData.value().getIdentity().size(), Name::Component("REVOKE"));
  m_publisher = Name::Component("self");
  recordName.append(m_publisher.value());
  
  std::shared_ptr<record::Record> record = std::make_shared<record::Record>();
  record->setName(recordName);
  record->setFreshnessPeriod(10_h);
  BOOST_ASSERT(m_revocationReason.has_value());
  record->setContent(recordtlv::encodeRecordContent(m_publicKeyHash, m_revocationReason.value()));
  m_keyChain.sign(*record, signingByKey(signingKeyName));
  return record;
}

void
State::getRecord(const record::Record& record)
{
  m_certName = record.getName();
  m_certName.set(record::Record::REVOKE_OFFSET, Name::Component("KEY"));
  m_certName.getPrefix(record::Record::PUBLISHER_OFFSET);
  recordtlv::decodeRecordContent(record.getContent(), *this);
}

std::shared_ptr<nack::Nack>
State::genNack(const Name& signingKeyName)
{
  auto nackName = m_certName;
  BOOST_ASSERT(m_publisher.has_value());
  nackName.append(m_publisher.value());
  nackName.append("nack").appendTimestamp();
  
  std::shared_ptr<nack::Nack> nack = std::make_shared<nack::Nack>();
  nack->setName(nackName);
  nack->setFreshnessPeriod(10_h);

  BOOST_ASSERT(m_nackCode.has_value());
  nack->setContent(nacktlv::encodeNackContent(m_nackCode.value()));
  m_keyChain.sign(*nack, signingByKey(signingKeyName));
  return nack;
}

void
State::getNack(const nack::Nack& nack)
{
  m_certName = nack.getName();
  m_certName.set(nack::Nack::REVOKE_OFFSET, Name::Component("KEY"));
  m_certName.getPrefix(nack::Nack::PUBLISHER_OFFSET);
  nacktlv::decodeNackContent(nack.getContent(), *this);
}

} // namespace record
} // namespace ndnrevoke

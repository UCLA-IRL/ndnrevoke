#include "state.hpp"
#include "record-encoder.hpp"
#include "nack.hpp"
#include "nack-encoder.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndnrevoke {
namespace state {

State::State(const Certificate& certData, ndn::KeyChain& keyChain)
  : m_certData(certData)
  , m_keyChain(keyChain)
{
  m_certName = m_certData.value().getName();
  auto buf = Sha256::computeDigest(m_certData.value().getPublicKey());
  m_publicKeyHash.assign(buf->begin(), buf->end());
}

// keychain may not be useful
State::State(const Name& certName, ndn::KeyChain& keyChain)
  : m_certName(certName)
  , m_keyChain(keyChain)
{
}

std::shared_ptr<record::Record>
State::genIssuerRecord(const Name& signingKeyName, ndn::time::milliseconds freshnessPeriod)
{
  if (!m_revocationReason.has_value()) {
    return nullptr;
  }
  auto recordName = m_certName;
  recordName.set(m_certData.value().getIdentity().size(), Name::Component("REVOKE"));
  m_publisher = Name::Component(m_certData.value().getIssuerId());
  recordName.append(m_publisher.value());
  
  std::shared_ptr<record::Record> record = std::make_shared<record::Record>();
  record->setName(recordName);
  record->setFreshnessPeriod(freshnessPeriod);
  record->setContent(recordtlv::encodeRecordContent(m_publicKeyHash, m_revocationReason.value()));
  m_keyChain.sign(*record, signingByKey(signingKeyName));
  return record;
}

std::shared_ptr<record::Record>
State::genOwnerRecord(const Name& signingKeyName, ndn::time::milliseconds freshnessPeriod)
{
  if (!m_revocationReason.has_value()) {
    return nullptr;
  }
  auto recordName = m_certName;
  recordName.set(Certificate::KEY_COMPONENT_OFFSET, Name::Component("REVOKE"));
  m_publisher = Name::Component("self");
  recordName.append(m_publisher.value());
  
  std::shared_ptr<record::Record> record = std::make_shared<record::Record>();
  record->setName(recordName);
  record->setFreshnessPeriod(freshnessPeriod);
  record->setContent(recordtlv::encodeRecordContent(m_publicKeyHash, m_revocationReason.value()));
  m_keyChain.sign(*record, signingByKey(signingKeyName));
  return record;
}

void
State::getRecord(const record::Record& record)
{
  m_certName = record.getName();
  m_certName.set(record::Record::REVOKE_OFFSET, Name::Component("KEY"));
  m_certName.erase(record::Record::PUBLISHER_OFFSET);
  recordtlv::decodeRecordContent(record.getContent(), *this);
}

std::shared_ptr<nack::Nack>
State::genNack(const Name& signingKeyName, ndn::time::milliseconds freshnessPeriod)
{
  if (!m_nackCode.has_value() || !m_publisher.has_value()) {
    return nullptr;
  }
  auto nackName = m_certName;
  nackName.append(m_publisher.value());
  nackName.append("nack").appendTimestamp();
  
  std::shared_ptr<nack::Nack> nack = std::make_shared<nack::Nack>();
  nack->setName(nackName);
  nack->setFreshnessPeriod(freshnessPeriod);
  nack->setContent(nacktlv::encodeNackContent(m_nackCode.value()));
  m_keyChain.sign(*nack, signingByKey(signingKeyName));
  return nack;
}

void
State::getNack(const nack::Nack& nack)
{
  m_certName = nack.getName();
  m_certName.set(nack::Nack::REVOKE_OFFSET, Name::Component("KEY"));
  m_certName.erase(nack::Nack::PUBLISHER_OFFSET);
  nacktlv::decodeNackContent(nack.getContent(), *this);
}

std::shared_ptr<Interest>
State::genSubmissionInterest(const Name& ctPrefix, const Certificate& cert, const Name& signingKeyName)
{
  // naming convention: /<CT prefix>/CT/submit/<type>/<paramDigest>
  auto interestName = ctPrefix;
  interestName.append("CT");
  interestName.append("submit").append("cert");
  auto interest = std::make_shared<Interest>(interestName);
  interest->setApplicationParameters(cert.wireEncode());
  m_keyChain.sign(*interest, signingByKey(signingKeyName));
  return interest;
}

std::shared_ptr<Interest>
State::genSubmissionInterest(const Name& ctPrefix, const record::Record& record, const Name& signingKeyName)
{
  // naming convention: /<CT prefix>/CT/submit/<type>/<paramDigest>
  auto interestName = ctPrefix;
  interestName.append("CT");
  interestName.append("submit").append("record");
  auto interest = std::make_shared<Interest>(interestName);
  interest->setApplicationParameters(record.wireEncode());
  m_keyChain.sign(*interest, signingByKey(signingKeyName));
  return interest;
}

} // namespace record
} // namespace ndnrevoke

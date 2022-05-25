#include "revoker.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
namespace ndnrevoke {
namespace revoker {

Revoker::Revoker(ndn::KeyChain& keyChain)
  : m_keyChain(keyChain)
{
}

std::shared_ptr<record::Record>
Revoker::revokeAsIssuer(const Certificate& certData, tlv::ReasonCode reason, uint64_t notBefore,
                        const ndn::time::milliseconds freshnessPeriod)
{
  return revokeAs(certData, reason, notBefore, certData.getIssuerId(), freshnessPeriod);
}

std::shared_ptr<record::Record>
Revoker::revokeAsOwner(const Certificate& certData, tlv::ReasonCode reason, uint64_t notBefore,
                      const ndn::time::milliseconds freshnessPeriod)
{
  return revokeAs(certData, reason, notBefore, Name::Component("self"), freshnessPeriod);
}

std::shared_ptr<record::Record>
Revoker::revokeAs(const Certificate& certData, tlv::ReasonCode reason, uint64_t notBefore,
                  const Name::Component id,
                  const ndn::time::milliseconds freshnessPeriod)
{
  auto recordName = certData.getName();
  recordName.set(certData.getIdentity().size(), Name::Component("REVOKE"));
  recordName.append(id);
  
  std::shared_ptr<record::Record> record = std::make_shared<record::Record>();

  // get the public key hash
  auto buf = Sha256::computeDigest(certData.getPublicKey());
  auto hash = ndn::make_span(reinterpret_cast<const uint8_t*>(buf->data()), buf->size());
  record->setName(recordName);
  record->setFreshnessPeriod(freshnessPeriod);
  record->setContentType(ndn::tlv::ContentType_Key);
  record->setContent(recordtlv::encodeRecordContent2(hash, reason, notBefore));

  if (id == Name::Component("self")) {
    auto selfIdentity = m_keyChain.getPib().getIdentity(certData.getIdentity());
    auto selfCert = selfIdentity.getDefaultKey().getDefaultCertificate();
    m_keyChain.sign(*record, signingByCertificate(selfCert));
  }
  else if (id == certData.getIssuerId()) {
    auto issuerName = certData.getKeyLocator().value().getName();
    m_keyChain.sign(*record, signingByCertificate(issuerName));
  }
  else {
    NDN_THROW(std::runtime_error("Neither Issuer or Owner for is in the keychain"));
  }
  return record;
}

} // namespace revoker
} // namespace ndnrevoke

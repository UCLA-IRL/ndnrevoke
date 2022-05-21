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

  Name signer = certData.getKeyLocator().value().getName();
  if (Certificate::isValidName(signer)) {
    // sign using certificate
     m_keyChain.sign(*record, signingByCertificate(signer));
  }
  else {
    // sign with key
    m_keyChain.sign(*record, signingByKey(signer));
  }
  return record;
}

} // namespace revoker
} // namespace ndnrevoke

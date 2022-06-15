#include "revoker.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
namespace ndnrevoke::revoker {

const ndn::time::milliseconds Revoker::recordFreshness = 8760_h;

Revoker::Revoker(ndn::KeyChain& keyChain)
  : m_keyChain(keyChain)
{
}

std::shared_ptr<Data>
Revoker::revokeAsIssuer(const Certificate& certData, const tlv::ReasonCode reason)
{
  return revokeAs(certData, reason, certData.getIssuerId());
}

std::shared_ptr<Data>
Revoker::revokeAsIssuer(const Certificate& certData, const tlv::ReasonCode reason,
                        const ndn::time::milliseconds notBefore,
                        const ndn::time::milliseconds freshnessPeriod)
{
  return revokeAs(certData, reason, notBefore, certData.getIssuerId(), freshnessPeriod);
}

std::shared_ptr<Data>
Revoker::revokeAsOwner(const Certificate& certData, const tlv::ReasonCode reason)
{
  return revokeAs(certData, reason, Name::Component("self"));
}

std::shared_ptr<Data>
Revoker::revokeAsOwner(const Certificate& certData, const tlv::ReasonCode reason,
                       const ndn::time::milliseconds notBefore,
                       const ndn::time::milliseconds freshnessPeriod)
{
  return revokeAs(certData, reason, notBefore, Name::Component("self"), freshnessPeriod);
}


std::shared_ptr<Data>
Revoker::revokeAs(const Certificate& certData, tlv::ReasonCode reason,
                  const Name::Component revokerId)
{
  auto recordName = certData.getName();
  recordName.set(certData.getIdentity().size(), Name::Component("REVOKE"));
  recordName.append(revokerId);

  // get the public key hash
  auto buf = Sha256::computeDigest(certData.getPublicKey());
  auto hash = ndn::make_span(reinterpret_cast<const uint8_t*>(buf->data()), buf->size());
  
  record::Record record;
  record.setName(recordName);
  record.setPublicKeyHash(hash);
  record.setReason(reason);
  record.setTimestamp(time::toUnixTimestamp(time::system_clock::now()));
  auto data = record.prepareData();
  data->setFreshnessPeriod(recordFreshness);
  return sign(data, certData, revokerId);
}

std::shared_ptr<Data>
Revoker::revokeAs(const Certificate& certData, tlv::ReasonCode reason,
                  const ndn::time::milliseconds notBefore,
                  const Name::Component revokerId,
                  const ndn::time::milliseconds freshnessPeriod)
{
  auto recordName = certData.getName();
  recordName.set(certData.getIdentity().size(), Name::Component("REVOKE"));
  recordName.append(revokerId);

  // get the public key hash
  auto buf = Sha256::computeDigest(certData.getPublicKey());
  auto hash = ndn::make_span(reinterpret_cast<const uint8_t*>(buf->data()), buf->size());
  
  record::Record record;
  record.setName(recordName);
  record.setPublicKeyHash(hash);
  record.setReason(reason);
  record.setTimestamp(time::toUnixTimestamp(time::system_clock::now()));
  record.setNotBefore(notBefore);
  auto data = record.prepareData();
  data->setFreshnessPeriod(freshnessPeriod);
  return sign(data, certData, revokerId);
}

std::shared_ptr<Data>
Revoker::sign(std::shared_ptr<Data> data, const Certificate& cert, const Name::Component revokerId)
{
  if (revokerId == Name::Component("self")) {
    auto idName = ndn::security::extractIdentityFromCertName(cert.getName());
    m_keyChain.sign(*data, signingByIdentity(idName));
  }
  else if (revokerId == cert.getIssuerId()) {
    auto issuerName = cert.getKeyLocator().value().getName();
    m_keyChain.sign(*data, signingByCertificate(issuerName));
  }
  else {
    NDN_THROW(std::runtime_error("Neither Issuer or Owner for the certificate is in the keychain"));
  }
  return data;
}

} // namespace ndnrevoke::revoker

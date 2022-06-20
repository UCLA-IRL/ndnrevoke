#include "checker-options.hpp"
#include "record.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
namespace ndnrevoke::checker {

NDN_LOG_INIT(ndnrevoke.checker);

const ssize_t CHECKER_MAX_RETRIES = 3;

CheckerOptions::CheckerOptions(ndn::Face& face,
                               const Certificate& certData,
                               const onValidCallback onValid, 
                               const onRevokedCallback onRevoked, 
                               const onFailureCallback onFailure)
  : m_face(face)
  , m_cert(certData)
  , m_vCb(onValid)
  , m_rCb(onRevoked)
  , m_fCb(onFailure)
{
}

std::shared_ptr<Interest>
CheckerOptions::makeInterest(const Name::Component& revoker)
{
  auto recordName = m_cert.getName();
  recordName.set(m_cert.getIdentity().size(), Name::Component("REVOKE"));
  recordName.append(revoker);
  auto interest = std::make_shared<Interest>(recordName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(true);
  interest->setForwardingHint({m_ledgerPrefix});
  return interest;
}

} // namespace ndnrevoke

#include "checker.hpp"
#include "record.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
namespace ndnrevoke::checker {

NDN_LOG_INIT(ndnrevoke.checker);

Checker::Checker(ndn::Face& face)
  : m_face(face)
{
}

void
Checker::doIssuerCheck(const Name ledgerPrefix, const Certificate& certData,
                       const onValidCallback onValid, 
                       const onRevokedCallback onRevoked, 
                       const onFailureCallback onFailure)
{
  doCheck(ledgerPrefix, certData, certData.getIssuerId(),
          onValid, onRevoked, onFailure);
}

void
Checker::doOwnerCheck(const Name ledgerPrefix, const Certificate& certData,
                      const onValidCallback onValid, 
                      const onRevokedCallback onRevoked, 
                      const onFailureCallback onFailure)
{
  doCheck(ledgerPrefix, certData, Name::Component("self"),
          onValid, onRevoked, onFailure);
}

void
Checker::doCheck(const Name ledgerPrefix, const Certificate& certData, const Name::Component& publisher,
                 const onValidCallback onValid, 
                 const onRevokedCallback onRevoked, 
                 const onFailureCallback onFailure)
{
  auto recordName = certData.getName();
  recordName.set(certData.getIdentity().size(), Name::Component("REVOKE"));
  recordName.append(publisher);
  Interest interest(recordName);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(true);
  interest.setForwardingHint({ledgerPrefix});

  CheckerCbs cbs;
  cbs.vCb = onValid;
  cbs.rCb = onRevoked;
  cbs.fCb = onFailure;
  try {
    m_states.insert(std::make_pair(recordName, cbs));
  }
  catch (std::exception& e) {
    NDN_LOG_ERROR("cannot set checker state");
  }
  m_face.expressInterest(interest,
                         std::bind(&Checker::onData, this, _1, _2),
                         std::bind(&Checker::onNack, this, _1, _2),
                         std::bind(&Checker::onTimeout, this, _1));
}

void
Checker::onData(const Interest&, const Data& data)
{
  // it this a record?
  Name dataName = data.getName();
  Name certName;
  certName = record::Record::getCertificateName(dataName);
  NDN_LOG_TRACE(certName);
  if (Certificate::isValidName(certName) &&
      dataName.at(record::Record::KEYWORD_OFFSET) == Name::Component("REVOKE")) {
    // TODO: validation
    auto iter = m_states.find(data.getName());
    if (iter == m_states.end()) {
      NDN_LOG_ERROR("cannot get checker state");
    }
    iter->second.rCb(record::Record(data));
    m_states.erase(iter);
    return;
  }

  // is this a nack?
  certName = nack::Nack::getCertificateName(dataName);
  NDN_LOG_TRACE(certName);
  if (Certificate::isValidName(certName) && 
      dataName.at(nack::Nack::TIMESTAMP_OFFSET).isTimestamp()) {
    // TODO: validation
    auto iter = m_states.find(data.getName().getPrefix(-2));
    if (iter == m_states.end()) {
      NDN_LOG_ERROR("cannot get checker state");
    }
    iter->second.vCb(nack::Nack(data));
    m_states.erase(iter);
    return;
  }
}


void
Checker::onNack(const Interest& interest, const ndn::lp::Nack& nack)
{
  auto iter = m_states.find(interest.getName());
  if (iter == m_states.end()) {
    NDN_LOG_ERROR("cannot get checker state");
  }
  NDN_LOG_ERROR("Interest " << interest << " nack:" << nack.getReason());
  iter->second.fCb("Interest nack");
  m_states.erase(iter);
}

void
Checker::onTimeout(const Interest& interest)
{
  auto iter = m_states.find(interest.getName());
  if (iter == m_states.end()) {
    NDN_LOG_ERROR("cannot get checker state");
  }
  if (iter->second.remainingRetry-- > 0) {
    NDN_LOG_DEBUG("Retrying Interest " << interest <<
                  ", remaining retries " << iter->second.remainingRetry);
    
    Interest retry(interest);
    retry.refreshNonce();
    m_face.expressInterest(retry,
                           std::bind(&Checker::onData, this, _1, _2),
                           std::bind(&Checker::onNack, this, _1, _2),
                           std::bind(&Checker::onTimeout, this, _1));    
  }
  else {
    iter->second.fCb("Interest timeout");
    m_states.erase(iter);
  }
}

} // namespace ndnrevoke

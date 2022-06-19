#include "checker.hpp"
#include "record.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
namespace ndnrevoke::checker {

NDN_LOG_INIT(ndnrevoke.checker);

Checker::Checker(ndn::Face& face, std::string schemaFile)
  : m_face(face)
{
  m_validator.load(schemaFile);
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
  cbs.cert = certData;
  cbs.vCb = onValid;
  cbs.rCb = onRevoked;
  cbs.fCb = onFailure;
  try {
    m_states.insert(std::make_pair(recordName, cbs));
    NDN_LOG_TRACE("checking: " << recordName);
  }
  catch (std::exception& e) {
    NDN_LOG_ERROR("Cannot set checker state");
  }
  m_face.expressInterest(interest,
                         std::bind(&Checker::onData, this, _1, _2),
                         std::bind(&Checker::onNack, this, _1, _2),
                         std::bind(&Checker::onTimeout, this, _1));
}

void
Checker::onData(const Interest&, const Data& data)
{
  m_validator.validate(data,
                       [this, data] (const Data&) {
                         NDN_LOG_DEBUG("Data conforms to trust schema");
                         onValidationSuccess(data);
                       },
                       [this, data] (const Data&, const ndn::security::ValidationError& error) {
                         NDN_LOG_ERROR("Error authenticating data: " << error);
                         onValidationFailure(data, error);
                       });
}

void
Checker::onValidationSuccess(const Data& data)
{
  // it this a record?
  Name dataName = data.getName();
  NDN_LOG_TRACE("Handling Validation Success: " << dataName);
  Name certName;
  if (record::Record::isValidName(dataName)) {
    auto iter = m_states.find(data.getName());
    if (iter == m_states.end()) {
      NDN_LOG_ERROR("Cannot get checker state");
      return;
    }
    iter->second.rCb(record::Record(data));
    m_states.erase(iter);
    return;
  }

  // is this a nack?
  if (nack::RecordNack::isValidName(dataName)) {
    nack::RecordNack nack(data);
    auto iter = m_states.find(nack.getRecordName());
    if (iter == m_states.end()) {
      NDN_LOG_ERROR("Cannot get checker state");
      return;
    }
    iter->second.vCb(nack);
    m_states.erase(iter);
    return;
  }
}

void
Checker::onValidationFailure(const Data& data, const ndn::security::ValidationError& error)
{
  // it this a record?
  Name dataName = data.getName();
  NDN_LOG_TRACE("Handling Validation Failure: " << dataName);
  Name certName;
  if (record::Record::isValidName(dataName)) {
    auto iter = m_states.find(data.getName());
    if (iter == m_states.end()) {
      iter->second.fCb(iter->second.cert, 
                       Error(Error::Code::IMPLEMENTATION_ERROR, "Cannot get checker state"));
      return;
    }
    iter->second.fCb(iter->second.cert, Error(Error::Code::VALIDATION_ERROR, error.getInfo()));
    m_states.erase(iter);
    return;
  }

  // is this a nack?
  if (nack::RecordNack::isValidName(dataName)) {
    auto iter = m_states.find(nack::RecordNack(data).getRecordName());
    if (iter == m_states.end()) {
      iter->second.fCb(iter->second.cert, 
                       Error(Error::Code::IMPLEMENTATION_ERROR, "Cannot get checker state"));
      return;
    }
    iter->second.fCb(iter->second.cert, Error(Error::Code::VALIDATION_ERROR, error.getInfo()));
    m_states.erase(iter);
    return;
  }
}

void
Checker::onNack(const Interest& interest, const ndn::lp::Nack& nack)
{
  auto iter = m_states.find(interest.getName());
  if (iter == m_states.end()) {
    NDN_LOG_ERROR("Cannot get checker state");
  }
  NDN_LOG_ERROR("Interest " << interest << " nack:" << nack.getReason());
  iter->second.fCb(iter->second.cert, 
                   Error(Error::Code::NACK, interest.getName().toUri()));
  m_states.erase(iter);
}

void
Checker::onTimeout(const Interest& interest)
{
  auto iter = m_states.find(interest.getName());
  if (iter == m_states.end()) {
    NDN_LOG_ERROR("Cannot get checker state");
    return;
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
    NDN_LOG_ERROR("Interest " << interest << " timeout");
    iter->second.fCb(iter->second.cert, 
                     Error(Error::Code::TIMEOUT, interest.getName().toUri()));
    m_states.erase(iter);
  }
}

} // namespace ndnrevoke

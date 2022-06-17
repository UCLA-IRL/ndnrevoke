#include "append/client-state.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndnrevoke::append {
namespace tlv = appendtlv;

NDN_LOG_INIT(ndnrevoke.append);

const ssize_t CLIENT_MAX_RETRIES = 3;

ClientState::ClientState(const Name& prefix, ndn::Face& face, uint64_t nonce,
                         ndn::KeyChain& keyChain, ndn::security::Validator& validator)
  : m_face(face)
  , m_options(prefix, nonce)
  , m_keyChain(keyChain)
  , m_validator(validator)
{
}

ClientState::ClientState(const Name& prefix, ndn::Face& face,
                         uint64_t nonce, const Name& fwHint,
                         ndn::KeyChain& keyChain, ndn::security::Validator& validator)
  : m_face(face)
  , m_options(prefix, nonce, fwHint)
  , m_keyChain(keyChain)
  , m_validator(validator)
{
}

void
ClientState::dispatchNotification(const Interest& interest)
{
  if (m_retryCount++ > CLIENT_MAX_RETRIES) {
    m_tCb(interest);
    delete this;
    return;
  }
  
  NDN_LOG_TRACE("Sending out notification " << interest);
  m_face.expressInterest(interest, 
    [this] (auto&&, const auto& notificationAck) {
      m_validator.validate(notificationAck, 
        [this, notificationAck] (const Data&) {
          NDN_LOG_DEBUG("ACK conforms to trust schema");
          onValidationSuccess(notificationAck);
        },
        [this, notificationAck] (const Data&, const ndn::security::ValidationError& error) {
          NDN_LOG_ERROR("Error authenticating ACK: " << error);
          m_fCb(notificationAck);
          delete this;
        });
    }, 
    [this] (const auto& i, auto& n) { m_nCb(i, n); delete this; },
    [this, interest] (const auto&) { dispatchNotification(interest);}
  );
}

void
ClientState::appendData(const Name& topic, const std::list<Data>& data, const onSuccessCallback successCb, 
                              const onFailureCallback failureCb, const onTimeoutCallback timeoutCb, const onNackCallback nackCb)
{
  // sanity check
  if (topic.empty() || data.size() == 0 || 
      data.front().getName().empty()) {
    NDN_LOG_ERROR("Empty data or topic, return");
    delete this;
    return;
  }
  
  m_sCb = successCb;
  m_fCb = failureCb;
  m_tCb = timeoutCb;
  m_nCb = nackCb;

  // dispatch notification
  dispatchNotification(*m_options.makeNotification(topic));
  // prepare submission
  Name filterName = m_options.makeInterestFilter(topic);
  auto filterId = m_face.setInterestFilter(filterName,
    [this, topic, data] (auto&&, const auto& i) {
      auto submission = m_options.makeSubmission(topic, data);
      m_keyChain.sign(*submission, ndn::signingByIdentity(m_options.getPrefix()));
      m_face.put(*submission);
      NDN_LOG_TRACE("Submitting " << submission);
    }
  );
  // handle the unregsiter task in destructor
  m_handle.handleFilter(filterId);
  NDN_LOG_TRACE("Registering filter for " << filterName);
}

void
ClientState::onValidationSuccess(const Data& data)
{
  auto statusList = m_options.praseAck(data);
  // if all success, onSuccess; otherwise, failure
  for (auto& status: statusList) {
    if (status == tlv::AppendStatus::SUCCESS) {
      continue;
    }
    else {
      m_fCb(data);
      delete this;
      return;
    }
  }
  NDN_LOG_TRACE("All succeeded\n");
  m_sCb(data);
  delete this;
}
} // namespace ndnrevoke::append

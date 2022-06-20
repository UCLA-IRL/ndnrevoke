#include "append/client-state.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndnrevoke::append {
namespace tlv = appendtlv;

NDN_LOG_INIT(ndnrevoke.append);

const ssize_t CLIENT_MAX_RETRIES = 3;

ClientState::ClientState(const Name& prefix, ndn::Face& face,
                         ndn::KeyChain& keyChain, ndn::security::Validator& validator)
  : m_face(face)
  , m_prefix(prefix)
  , m_keyChain(keyChain)
  , m_validator(validator)
{
}

ClientState::ClientState(const Name& prefix, ndn::Face& face,
                         const Name& fwHint,
                         ndn::KeyChain& keyChain, ndn::security::Validator& validator)
  : m_face(face)
  , m_prefix(prefix)
  , m_keyChain(keyChain)
  , m_validator(validator)
{
}

void
ClientState::dispatchNotification(const std::shared_ptr<ClientOptions>& options, const std::list<Data>& data)
{
  auto interest = options->makeNotification();
  if (m_retryCount++ > CLIENT_MAX_RETRIES) {
    options->onFailure(data, Error(Error::Code::TIMEOUT, interest->getName().toUri()));
    return;
  }
  NDN_LOG_TRACE("Sending out notification " << *interest);
  m_face.expressInterest(*interest, 
    [this, options, data] (auto&&, const auto& notificationAck) {
      m_validator.validate(notificationAck, 
        [this, options, data, notificationAck] (const Data&) {
          NDN_LOG_DEBUG("ACK conforms to trust schema");
          onValidationSuccess(options, data, notificationAck);
        },
        [this, options, data, notificationAck] (const Data&, const ndn::security::ValidationError& error) {
          onValidationFailure(options, data, error);
        });
    }, 
    [options, data] (const auto& i, auto& n) {
      NDN_LOG_ERROR("Notification Nack: " << n.getReason()); 
      options->onFailure(data, Error(Error::Code::NACK, i.getName().toUri()));
    },
    [this, options, data] (const auto&) { dispatchNotification(options, data);}
  );
}

uint64_t
ClientState::appendData(const Name& topic, const std::list<Data>& data,
                        const ClientOptions::onSuccessCallback onSuccess,
                        const ClientOptions::onFailureCallback onFailure)
{
  // sanity check
  if (topic.empty() || data.size() == 0 || 
      data.front().getName().empty()) {
    NDN_LOG_ERROR("Empty data or topic, return");
    return appendtlv::InvalidNonce;
  }

  auto options = std::make_shared<ClientOptions>(m_prefix, topic,
      ndn::random::generateSecureWord64(), onSuccess, onFailure);
  // prepare submission
  Name filterName = options->makeInterestFilter();
  auto filterId = m_face.setInterestFilter(filterName,
    [this, options, data] (auto&&, const auto& i) {
      auto submission = options->makeSubmission(data);
      m_keyChain.sign(*submission, ndn::signingByIdentity(options->getPrefix()));
      m_face.put(*submission);
      NDN_LOG_TRACE("Submitting " << *submission);  
    }
  );
  // handle the unregsiter task in destructor
  m_handle.handleFilter(filterId);
  NDN_LOG_TRACE("Registering filter for " << filterName);
  dispatchNotification(options, data);
  return options->getNonce();
}

void
ClientState::onValidationSuccess(const std::shared_ptr<ClientOptions>& options, const std::list<Data>& data, const Data& ack)
{
  auto statusList = options->praseAck(ack);
  // if all success, onSuccess; otherwise, failure
  for (auto& status: statusList) {
    if (status == tlv::AppendStatus::SUCCESS) {
      continue;
    }
    else {
      NDN_LOG_TRACE("There are individual submissions failed by CT");
    }
  }
  m_retryCount = 0;
  options->onSuccess(data, ack);
}

void
ClientState::onValidationFailure(const std::shared_ptr<ClientOptions>& options, const std::list<Data>& data,
                                 const ndn::security::ValidationError& error)
{
  NDN_LOG_ERROR("Error authenticating ACK: " << error);
  options->onFailure(data, Error(Error::Code::VALIDATION_ERROR, error.getInfo()));
}

} // namespace ndnrevoke::append

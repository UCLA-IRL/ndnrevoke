#include "append/ct-state.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndnrevoke::append {
NDN_LOG_INIT(ndnrevoke.append);


const ssize_t CT_MAX_RETRIES = 5;

CtState::CtState(const Name& prefix, const Name& topic, ndn::Face& face, 
                 ndn::KeyChain& keyChain, ndn::security::Validator& validator)
  : m_prefix(prefix)
  , m_face(face)
  , m_topic(topic)
  , m_keyChain(keyChain)
  , m_validator(validator)
{
}

void
CtState::serveClient(std::shared_ptr<ClientOptions> client)
{
  auto fetcher =  m_options.makeFetcher(*client);
  if (m_retryCount++ > CT_MAX_RETRIES) {
    NDN_LOG_ERROR("Interest " << fetcher << " run out of " << CT_MAX_RETRIES << " retries");
    // acking notification
    auto ack = m_options.makeNotificationAck(*client, {AppendStatus::FAILURE_TIMEOUT});
    m_keyChain.sign(*ack, ndn::signingByIdentity(m_prefix));
    m_face.put(*ack);
    NDN_LOG_TRACE("Putting notification ack");
    return;
  }
  
  NDN_LOG_TRACE("Sending out interest " << *fetcher);
  m_face.expressInterest(*fetcher, 
    [this, client] (auto& i, const auto& submission) {
      NDN_LOG_TRACE("Receiving submission data " << submission.getName());
      m_validator.validate(submission, 
        [this, submission, client] (const Data&) {
          NDN_LOG_DEBUG("D1 conforms to trust schema");
          onValidationSuccess(submission, client);
        },
        [this, submission, client] (const Data&, const ndn::security::ValidationError& error) {
          NDN_LOG_ERROR("Error authenticating D1: " << error);
          onValidationFailure(submission, error, client);
        });
    },
    [this, client] (const auto& i, auto& n) {
      // acking notification
      auto ack = m_options.makeNotificationAck(*client, {AppendStatus::FAILURE_NACK});
      m_keyChain.sign(*ack, ndn::signingByIdentity(m_prefix));
      m_face.put(*ack);
      NDN_LOG_TRACE("Putting notification ack");
    },
    [this, client] (const auto& i) {
      NDN_LOG_TRACE("Retry");
      serveClient(client);
    }
  );
}

void
CtState::listen(const UpdateCallback& onUpdateCallback)
{
  if (m_topic.empty()) {
    NDN_LOG_TRACE("No topic to listen, return\n");
    return;
  }
  m_onUpdate = onUpdateCallback;

  auto filterId = m_face.setInterestFilter(Name(m_topic).append("notify"),
    [this] (auto&&, const auto& i) { 
      NDN_LOG_TRACE("Receiving notification " << i);
      auto client = m_options.praseNotification(i);
      auto fetcher = m_options.makeFetcher(*client);
      serveClient(client);
    });
  m_handle.handleFilter(filterId);
  NDN_LOG_TRACE("Registering filter for notification " << Name(m_topic).append("notify"));
}

void
CtState::onValidationSuccess(const Data& data, std::shared_ptr<ClientOptions> client)
{
  auto content = data.getContent();

  std::list<AppendStatus> statusList;
  m_retryCount = 0;
  content.parse();
  ssize_t count = 0;
  AppendStatus statusCode;
  for (const auto &it : content.elements()) {
      switch (it.type()) {
      case ndn::tlv::Data:
          count++;
          statusCode = m_onUpdate(Data(it));
          statusList.push_back(statusCode);
          break;
      default:
          if (ndn::tlv::isCriticalType(it.type())) {
            NDN_THROW(std::runtime_error("Unrecognized TLV Type: " + std::to_string(it.type())));
          }
          else {
            //ignore
          }
          break;
      }
    // acking notification
    auto ack = m_options.makeNotificationAck(*client, statusList);
    m_keyChain.sign(*ack, ndn::signingByIdentity(m_prefix));
    m_face.put(*ack);
    NDN_LOG_TRACE("Putting notification ack");
  }
}

void
CtState::onValidationFailure(const Data& data, const ndn::security::ValidationError& error,
                              std::shared_ptr<ClientOptions> client)
{
  // acking notification
  NDN_LOG_TRACE("Putting notification ack");
  auto ack = m_options.makeNotificationAck(*client, {AppendStatus::FAILURE_VALIDATION_PROTO});
  m_keyChain.sign(*ack, ndn::signingByIdentity(m_prefix));
  m_face.put(*ack);
}
} // namespace ndnrevoke::append

#include "append/append-encoder.hpp"
#include "append/append-common.hpp"
#include "append/handle-client.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndnrevoke {
namespace append { 

NDN_LOG_INIT(ndnrevoke.append);

const ssize_t MAX_RETRIES = 6;
const uint64_t INVALID_NONCE = (uint64_t)(-1);

HandleClient::HandleClient(const ndn::Name& prefix, ndn::Face& face, ndn::KeyChain& keyChain)
  : Handle(prefix, face, keyChain)
{
  if (m_localPrefix.empty()) {
    NDN_LOG_ERROR("Cannot construct, local prefix is not set\n");
    return;
  }

  // register reachable prefix to NFD
  auto prefixId = m_face.registerPrefix(m_localPrefix, 
    [&] (const Name& name) {
      // notice: this only register FIB to Face, not NFD.
      // register for /<prefix>/msg
      auto filterId = m_face.setInterestFilter(Name(m_localPrefix).append("msg"), 
        [this] (auto&&, const auto& i) {
          onSubmissionFetchingInterest(i);
        }
      );
      m_interestFilterHandles.push_back(filterId);
      NDN_LOG_TRACE("Registering filter for " << Name(m_localPrefix).append("msg"));
    },
    [&] (auto&&, const auto& reason) {
      NDN_LOG_ERROR("Failed to register prefix with the local forwarder (" << reason << ")\n");
      m_face.shutdown();
    }
  );
  m_registeredPrefixHandles.push_back(prefixId);
}

void
HandleClient::dispatchNotification(const Interest& interest, const uint64_t nonce)
{
  if (m_retryCount++ > MAX_RETRIES) {
    NDN_LOG_ERROR("Running out of retries: " << m_retryCount << " retries");
    auto iter = m_callback.find(nonce);
    // no more retransmissions, directly timeout
    if (iter != m_callback.end()) {
      iter->second.onTimeout(interest);
      m_callback.erase(iter);
    }
    return;
  }
  
  NDN_LOG_TRACE("Sending out interest " << interest);
  m_face.expressInterest(interest, 
    [=] (auto&&, const auto& i) { onNotificationAck(nonce, i);}, 
    [=] (const auto& i, auto& n) {
      auto iter = m_callback.find(nonce);
      if (iter != m_callback.end()) {
        iter->second.onNack(i, n);
        m_callback.erase(iter);
      }
    },
    [=] (const auto& i) {
      dispatchNotification(interest, nonce);
    }
  );
}

std::shared_ptr<Interest>
HandleClient::makeNotification(const ndn::Name& topic, uint64_t nonce)
{
  auto notification = std::make_shared<Interest>(Name(topic).append("notify"));
  // notification parameter: m_prefix, [m_forwardingHint], nonce
  auto param = appendtlv::encodeAppendParameters(m_localPrefix, nonce, m_forwardingHint);
  notification->setApplicationParameters(param);
  return notification;
}

uint64_t
HandleClient::appendData(const ndn::Name& topic, std::list<Data> data)
{
  // sanity check
  if (topic.empty() || data.size() == 0 || 
      data.front().getName().empty()) {
    NDN_LOG_ERROR("Empty data or topic, return");
    return INVALID_NONCE;
  }
  const uint64_t nonce = ndn::random::generateSecureWord64();
  m_nonceMap.insert({nonce, data});
  auto notification = makeNotification(topic, nonce);
  dispatchNotification(*notification, nonce);
  return nonce;
}

uint64_t
HandleClient::appendData(const ndn::Name& topic, std::list<Data> data, const onSuccessCallback successCb, 
                         const onFailureCallback failureCb, const onTimeoutCallback timeoutCb, const onNackCallback nackCb)
{
  uint64_t nonce = appendData(topic, data);
  if (nonce != INVALID_NONCE) {
    m_callback.insert({nonce, {successCb, failureCb, timeoutCb, nackCb}});
  }
  return nonce;
}

void
HandleClient::onNotificationAck(const uint64_t nonce, const Data& data)
{
  // reset retryCount
  m_retryCount = 0;

  auto content = data.getContent();
  content.parse();
  
  // sanity check
  if (m_nonceMap.find(nonce) != m_nonceMap.end()) {
    m_nonceMap.erase(nonce);
  }
  else { 
    NDN_LOG_ERROR("Unrecognized nonce " << nonce << ", abort");
    return;
  }

  std::list<uint64_t> statusList;
  auto iter = m_callback.find(nonce);
  for (const auto &item : content.elements()) {
    switch (item.type()) {
      case tlv::AppendStatusCode:
        statusList.push_back(readNonNegativeInteger(item));
        break;
      default:
        if (ndn::tlv::isCriticalType(item.type())) {
          NDN_THROW(std::runtime_error("Unrecognized TLV Type: " + std::to_string(item.type())));
        }
        else {
          //ignore
        }
        break;
    }
  }

  // if all success, onSuccess; otherwise, failure
  for (auto& status: statusList) {
    if (static_cast<tlv::AppendStatus>(status) == tlv::AppendStatus::SUCCESS) {
      continue;
    }
    else {
      NDN_LOG_TRACE("Not all succeeded\n");
      if (iter != m_callback.end()) {
        iter->second.onFailure(data);
        m_callback.erase(iter);
        return;
      }
    }
  }
  NDN_LOG_TRACE("All succeeded\n");
  if (iter != m_callback.end()) {
    iter->second.onSuccess(data);
    m_callback.erase(iter);
  }
}

void
HandleClient::onSubmissionFetchingInterest(const Interest& interest)
{
  // Interest: /<m_prefix>/msg/<topic>/<nonce>
  // <topic> should be /<ct-prefix>/append

  const ssize_t NONCE_OFFSET = -1;
  uint64_t nonce = interest.getName().get(NONCE_OFFSET).toNumber();
  NDN_LOG_TRACE("Submission fetching: [nonce " << nonce << " ]");
  
  auto iter = m_nonceMap.find(nonce);
  if (iter != m_nonceMap.end()) {
    // putting back
    int dataCount = 0;
    Block content(ndn::tlv::Content);
    for (auto& item : iter->second) {
      dataCount++;
      content.push_back(item.wireEncode());
    }
    content.encode();

    NDN_LOG_TRACE("Putting " << std::to_string(dataCount) << " Data into submission");
    Data submission(interest.getName());
    submission.setContent(content);
    m_keyChain.sign(submission, ndn::signingByIdentity(m_localPrefix));
    m_face.put(submission);
  }
  else {
    NDN_LOG_DEBUG("Unrecognized nonce " << nonce);
  }
}

} // namespace append
} // namespace ndnrevoke

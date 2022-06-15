#include "append/append-common.hpp"
#include "append/handle-ct.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndnrevoke::append {

NDN_LOG_INIT(ndnrevoke.append);


const ssize_t MAX_RETRIES = 2;

std::string statusToString(tlv::AppendStatus status)
{
  switch (status) {
    case tlv::AppendStatus::SUCCESS:
      return "Success";
    case tlv::AppendStatus::FAILURE_NACK:
      return "FAILURE_NACK";
    case tlv::AppendStatus::FAILURE_TIMEOUT:
      return "FAILURE_TIMEOUT";
    case tlv::AppendStatus::FAILURE_NX_CERT:
      return "FAILURE_NX_CERT";
    case tlv::AppendStatus::FAILURE_STORAGE:
      return "FAILURE_STORAGE";
    case tlv::AppendStatus::NOTINITIALIZED:
      return "NOTINITIALIZED";
    default:
      return "Unrecognized status";
  }
}

HandleCt::HandleCt(const ndn::Name& prefix, ndn::Face& face, ndn::KeyChain& keyChain)
  : Handle(prefix, face, keyChain)
{
}

std::shared_ptr<Data>
HandleCt::makeNotificationAck(const Name& notificationName, const std::list<tlv::AppendStatus> statusList)
{
  auto data = std::make_shared<Data>(notificationName);
  // acking notification
  Block content(ndn::tlv::Content);
  for (auto& status : statusList) {
    // can use bitmap to optimize, but later
    content.push_back(ndn::makeNonNegativeIntegerBlock(tlv::AppendStatusCode, static_cast<uint64_t>(status)));
  }
  content.encode();
  data->setContent(content);
  m_keyChain.sign(*data, ndn::signingByIdentity(m_localPrefix));
  return data;
}

void
HandleCt::dispatchInterest(const Interest& interest, const uint64_t nonce)
{
  auto item = m_nonceMap.find(nonce);
  if (item == m_nonceMap.end()) {
    return;
  }

  if (item->second.retryCount++ > MAX_RETRIES) {
    NDN_LOG_ERROR("Interest " << interest << " run out of " << item->second.retryCount << " retries");
    // acking notification
    m_face.put(*makeNotificationAck(item->second.interestName, {tlv::AppendStatus::FAILURE_TIMEOUT}));
    NDN_LOG_TRACE("Putting notification ack");
    m_nonceMap.erase(nonce);
    return;
  }
  
  NDN_LOG_TRACE("Sending out interest " << interest);
  m_face.expressInterest(interest, 
    [=] (auto& i, const auto& d) { onSubmissionData(i, d);},
    [=] (const auto& i, auto& n) {
      // acking notification
      m_face.put(*makeNotificationAck(item->second.interestName, {tlv::AppendStatus::FAILURE_NACK}));
      NDN_LOG_TRACE("Putting notification ack");
      m_nonceMap.erase(nonce);
    },
    [=] (const auto& i) {
      NDN_LOG_TRACE("Retry");
      dispatchInterest(interest, nonce);
    }
  );
}

void
HandleCt::listenOnTopic(Name& topic, const UpdateCallback& onUpdateCallback)
{
  m_topic = topic;
  m_updateCallback = onUpdateCallback;
  if (m_topic.empty()) {
    NDN_LOG_TRACE("No topic to listen, return\n");
    return;
  }
  else {
    auto prefixId = m_face.registerPrefix(m_topic,[&] (const Name& name) {
      // register for each record Zone
      // notice: this only register FIB to Face, not NFD.
      auto filterId = m_face.setInterestFilter(Name(m_topic).append("notify"), [=] (auto&&, const auto& i) { onNotification(i); });
      m_interestFilterHandles.push_back(filterId);
      NDN_LOG_TRACE("Registering filter for notification " << Name(m_topic).append("notify"));
    },
    [] (auto&&, const auto& reason) { 
      NDN_LOG_ERROR("Failed to register prefix in local hub's daemon, REASON: " << reason);
    });
    m_registeredPrefixHandles.push_back(prefixId);
   }
}

void
HandleCt::onNotification(Interest interest)
{
  // Interest: <topic>/<nonce>/<paramDigest>
  // <topic> should be /<ct-prefix>/append
  appendtlv::AppenderInfo info;
  appendtlv::decodeAppendParameters(interest.getApplicationParameters(), info);
  
  if (m_nonceMap.find(info.nonce) != m_nonceMap.end()) {
    NDN_LOG_TRACE("Old notification: [nonce " << info.nonce << " ] [remotePrefix " << info.remotePrefix << " ]");
    return;
  }
  
  NDN_LOG_TRACE("New notification: [nonce " << info.nonce << " ] [remotePrefix " << info.remotePrefix << " ]");
  info.interestName = interest.getName();
  info.retryCount = 0;
  m_nonceMap.insert({info.nonce, info});

  // send interst: /<remotePrefix>/msg/<topic>/<nonce>
  Interest submissionFetcher(Name(info.remotePrefix).append("msg").append(m_topic)
                                                    .appendNumber(info.nonce));
  if (!info.forwardingHint.empty()) {
    submissionFetcher.setForwardingHint({info.forwardingHint});
  }

  // ideally we need fill in all three callbacks
  dispatchInterest(submissionFetcher, info.nonce);
}

void
HandleCt::onSubmissionData(const Interest& interest, const Data& data)
{
  // /ndn/site1/abc/msg/ndn/append/%29%40%87u%89%F9%8D%E4
  NDN_LOG_TRACE("Receiving submission data " << data.getName());
  auto content = data.getContent();
  const ssize_t NONCE_OFFSET = -1;
  const uint64_t nonce = data.getName().at(NONCE_OFFSET).toNumber();
  auto item = m_nonceMap.find(nonce);

  std::list<tlv::AppendStatus> statusList;
  if (item != m_nonceMap.end()) {
    item->second.retryCount = 0;
    content.parse();
    ssize_t count = 0;
    tlv::AppendStatus statusCode;
    for (const auto &item : content.elements()) {
      switch (item.type()) {
        case ndn::tlv::Data:
          count++;
          // ideally we should run validator here
          statusCode = m_updateCallback(Data(item));
          NDN_LOG_TRACE("Status code for Data " << count << " is " << statusToString(statusCode));
          statusList.push_back(statusCode);
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

    // acking notification
    m_face.put(*makeNotificationAck(item->second.interestName, statusList));
    NDN_LOG_TRACE("Putting notification ack");
    m_nonceMap.erase(nonce);
  }
  else {
    NDN_LOG_TRACE("Unrecognized nonce: " << nonce);
  }
}

} // namespace ndnrevoke::append

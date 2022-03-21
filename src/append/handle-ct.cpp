#include "append/append-common.hpp"
#include "append/handle-ct.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndnrevoke {
namespace append {

NDN_LOG_INIT(ndnrevoke.append);

HandleCt::HandleCt(const ndn::Name& prefix, ndn::Face& face, ndn::KeyChain& keyChain)
  : Handle(prefix, face, keyChain)
{
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
      auto filterId = m_face.setInterestFilter(Name(m_topic).append("notify"), [this] (auto&&, const auto& i) { onNotification(i); });
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
  NDN_LOG_TRACE("New notification: [nonce " << info.nonce << " ] [remotePrefix " << info.remotePrefix << " ]");
  info.interestName = interest.getName();
  m_nonceMap.insert({info.nonce, info});

  // send interst: /<remotePrefix>/msg/<topic>/<nonce>
  Interest commandFetcher(Name(info.remotePrefix).append("msg").append(m_topic)
                                                 .appendNumber(info.nonce));
  if (!info.commandForwardingHint.empty()) {
    commandFetcher.setForwardingHint({info.commandForwardingHint});
  }

  // ideally we need fill in all three callbacks
  commandFetcher.setCanBePrefix(false);
  m_face.expressInterest(commandFetcher, [this] (auto&&, const auto& i) { onCommandData(i); }, nullptr, nullptr);
}

void
HandleCt::onCommandData(Data data)
{
  // /ndn/site1/abc/msg/ndn/append/%29%40%87u%89%F9%8D%E4
  auto content = data.getContent();
  const ssize_t NONCE_OFFSET = -1;
  const uint64_t nonce = data.getName().at(NONCE_OFFSET).toNumber();
  auto item = m_nonceMap.find(nonce);

  if (item != m_nonceMap.end()) {
    // fetch the actual data
    appendtlv::decodeAppendContent(content, item->second);
    Interest dataFetcher;
    
    if (!item->second.dataName.empty()) {
      dataFetcher.setName(item->second.dataName);
    }
    else {
      NDN_LOG_ERROR("No corresponding notification available, return");
      return;
    }

    if (!item->second.dataForwardingHint.empty()) {
        dataFetcher.setForwardingHint({item->second.dataForwardingHint});
    }
    // ideally we need fill in all three callbacks
    m_face.expressInterest(dataFetcher, [this, item, content] (auto&&, const auto& i) {
      NDN_LOG_TRACE("Retrieve data " << i.getName());
      NDN_LOG_TRACE("New command: [nonce " << item->second.nonce << " ] [dataName " 
                                            << item->second.dataName << " ]");
      // acking notification
      m_face.put(*makeNotificationAck(item->second.interestName, tlv::AppendStatus::SUCCESS));
      NDN_LOG_TRACE("Putting notification ack");

      // triggering callback
      m_updateCallback(i);
    },
    [this, item] (auto&, auto&) {
      m_face.put(*makeNotificationAck(item->second.interestName, tlv::AppendStatus::FAILURE_NACK));
      NDN_LOG_TRACE("Putting notification ack");        
    }, 
    [this, item] (auto&) {
      m_face.put(*makeNotificationAck(item->second.interestName, tlv::AppendStatus::FAILURE_TIMEOUT));
      NDN_LOG_TRACE("Putting notification ack");        
    });
  }
  m_nonceMap.erase(nonce);
}

std::shared_ptr<Data>
HandleCt::makeNotificationAck(const Name& notificationName, const tlv::AppendStatus status)
{
  auto data = std::make_shared<Data>(notificationName);
  // acking notification
  data->setContent(ndn::makeNonNegativeIntegerBlock(tlv::AppendStatusCode, static_cast<uint64_t>(status)));
  m_keyChain.sign(*data, ndn::signingByIdentity(m_localPrefix));
  return data;
}
} // namespace append
} // namespace ndnrevoke

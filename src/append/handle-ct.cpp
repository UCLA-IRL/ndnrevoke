#include "append/append-encoder.hpp"
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
HandleCt::listenOnTopic(Name& topic)
{
  m_topic = topic;
  if (m_topic.empty()) {
    NDN_LOG_TRACE("No topic to listen, return\n");
    return;
  }
  else {
  auto prefixId = m_face.registerPrefix(m_topic,[&] (const Name& name) {
    // register for each record Zone
    // notice: this only register FIB to Face, not NFD.
    auto filterId = m_face.setInterestFilter(Name(m_topic).append("notify"), [this] (auto&&, const auto& i) { onNotification(i); });
    NDN_LOG_TRACE("Registering filter for notification " << Name(m_topic).append("notify"));
    },
    [this] (auto&&, const auto& reason) { NDN_LOG_ERROR("Failed to register prefix in local hub's daemon, REASON: " << reason); });
   }
}

void
HandleCt::onNotification(Interest interest)
{
  // Interest: <topic>/<nonce>/<paramDigest>
  // <topic> should be /<ct-prefix>/append
  NDN_LOG_DEBUG(interest);

  appendtlv::AppenderInfo info;
  appendtlv::decodeAppendParameters(interest.getApplicationParameters(), info);
  NDN_LOG_DEBUG("nonce = " << info.nonce << " remotePrefix = " << info.remotePrefix);
  addNonce(info.nonce, info.remotePrefix);

  // send interst: /<remotePrefix>/msg/<topic>/<nonce>
  Interest commandFetcher(Name(info.remotePrefix).append("msg").append(m_topic)
                                                 .appendNumber(info.nonce));
  if (!info.commandForwardingHint.empty()) {
    commandFetcher.setForwardingHint({info.commandForwardingHint});
  }

  // do we really need to sign notification interest? I don't think so?
  // m_keyChain.sign(notification);

  // ideally we need fill in all three callbacks
  m_face.expressInterest(commandFetcher, [this] (auto&&, const auto& i) { onCommandData(i); }, nullptr, nullptr);
  NDN_LOG_DEBUG(commandFetcher);
}

void
HandleCt::onCommandData(Data data)
{
  NDN_LOG_DEBUG(data);
  auto content = data.getContent();
  appendtlv::AppenderInfo info;
  appendtlv::decodeAppendContent(content, info);

  auto item = findNonce(info.nonce);
  NDN_LOG_DEBUG("nonce = " << info.nonce << " prefix = " << item->second);
  deleteNonce(info.nonce);

  // fetch the actual data
  Interest dataFetcher(info.dataName);
  if (!info.dataForwardingHint.empty()) {
    dataFetcher.setForwardingHint({info.dataForwardingHint});
  }

  // do we really need to sign notification interest? I don't think so?
  // m_keyChain.sign(notification);

  // ideally we need fill in all three callbacks
  m_face.expressInterest(dataFetcher, [this] (auto&&, const auto& i) {
    m_updateCallback(i);
  }, nullptr, nullptr);

}



} // namespace append
} // namespace ndnrevoke

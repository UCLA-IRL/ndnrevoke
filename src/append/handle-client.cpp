#include "append/append-encoder.hpp"
#include "append/append-common.hpp"
#include "append/handle-client.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndnrevoke {
namespace append {

NDN_LOG_INIT(ndnrevoke.append);


HandleClient::HandleClient(const ndn::Name& prefix, ndn::Face& face, ndn::KeyChain& keyChain)
  : Handle(prefix, face, keyChain)
{
  if (m_localPrefix.empty()) {
    NDN_LOG_ERROR("Cannot construct, local prefix is not set\n");
    return;
  }

  // register reachable prefix to NFD
  auto prefixId = m_face.registerPrefix(
    m_localPrefix, 
    [&] (const Name& name) {
      // notice: this only register FIB to Face, not NFD.
      // register for /<prefix>/msg
      auto filterId = m_face.setInterestFilter(Name(m_localPrefix).append("msg"), [this] (auto&&, const auto& i)
          { onCommandFetchingInterest(i); });
      m_interestFilterHandles.push_back(filterId);
      NDN_LOG_TRACE("Registering filter for /<m_localPrefix>/msg " << Name(m_localPrefix).append("msg"));
    },
    [&] (auto&&, const auto& reason) {   
      NDN_LOG_ERROR("Failed to register prefix with the local forwarder (" << reason << ")\n");
      m_face.shutdown(); });
  m_registeredPrefixHandles.push_back(prefixId);
}

void
HandleClient::appendData(const ndn::Name& topic, Data& data)
{
  // sanity check
  if (topic.empty() || data.getName().empty()) {
    NDN_LOG_ERROR("Empty data or topic, return");
    return;
  }
  uint64_t nonce = ndn::random::generateSecureWord64();
  m_nonceMap.insert({nonce, data});
  runNotify(topic, nonce, data);
}

void
HandleClient::runNotify(const ndn::Name& topic, uint64_t nonce, Data data)
{
  Interest notification(Name(topic).append("notify"));

  // better to separate into a specific encoder
  // notification parameter: m_prefix, [m_forwardingHint], nonce
  auto param = appendtlv::encodeAppendParameters(m_localPrefix, ndn::random::generateSecureWord64(), m_forwardingHint);
  notification.setApplicationParameters(param);

  // do we really need to sign notification interest? I don't think so?
  // m_keyChain.sign(notification);

  // ideally we need fill in all three callbacks
  m_face.expressInterest(notification, [this] (auto&&, const auto& i) { onNotificationAck(i);}, nullptr, nullptr);
}

void
HandleClient::onNotificationAck(const Data& data)
{
  auto content = data.getContent();
  content.parse();
  tlv::AppendStatus status = tlv::AppendStatus::NOTINITIALIZED;
  for (const auto &item : content.elements()) {
    switch (item.type()) {
      case tlv::AppendStatusCode:
        status = static_cast<tlv::AppendStatus>(readNonNegativeInteger(item));
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
  switch (status) {
    case tlv::AppendStatus::NOTINITIALIZED:
      NDN_LOG_ERROR("Not initialized status code");
      break;
    case tlv::AppendStatus::SUCCESS:
      NDN_LOG_TRACE("Append succeeded");
      break;
    case tlv::AppendStatus::FAILURE:
      NDN_LOG_TRACE("Append failed");
      break;
    default:
      NDN_LOG_TRACE("Unrecognized status code: " << static_cast<uint64_t>(status));
      break;
  }
}

void
HandleClient::onCommandFetchingInterest(const Interest& interest)
{
  // Interest: /<m_prefix>/msg/<topic>/<nonce>
  // <topic> should be /<ct-prefix>/append

  const ssize_t NONCE_OFFSET = -1;
  uint64_t nonce = interest.getName().get(NONCE_OFFSET).toNumber();
  NDN_LOG_TRACE("Command fetching: [nonce " << nonce << " ]");
  
  Data command(interest.getName());
  auto content = appendtlv::encodeAppendContent(m_dataName, m_forwardingHint);
  command.setContent(content);
  m_keyChain.sign(command, ndn::signingByIdentity(m_localPrefix));
  m_face.put(command);

  auto iter = m_nonceMap.find(nonce);
  if (iter != m_nonceMap.end()) {
    // register for actual data fetching interest
    NDN_LOG_TRACE("Setting Interest filter for " << iter->second.getName());
    auto prefixId = m_face.setInterestFilter(ndn::InterestFilter(iter->second.getName()), [this, nonce] (auto&&, const auto& interest) {
                            auto iter = m_nonceMap.find(nonce);
                            if (iter != m_nonceMap.end()) {
                              m_face.put(iter->second);
                              m_nonceMap.erase(nonce);
                            }
                            else {
                              NDN_LOG_DEBUG("So data for nonce " << nonce);
                            }},
                            [&] (auto&&, const auto& reason) {
                              NDN_LOG_ERROR("Failed to register prefix in local hub's daemon, REASON: " << reason);
                            });
    m_registeredPrefixHandles.push_back(prefixId);    
  }
  else {
    NDN_LOG_DEBUG("Unrecognized nonce " << nonce);
  }
}

} // namespace append
} // namespace ndnrevoke

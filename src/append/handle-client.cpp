#include "append/append-encoder.hpp"
#include "append/append-common.hpp"
#include "append/handle-client.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndnrevoke {
namespace append {

NDN_LOG_INIT(ndnrevoke.append);


void
HandleClient::runNotify()
{
  Interest notification(Name(m_remotePrefix).append("notify"));

  // better to separate into a specific encoder
  // notification parameter: m_prefix, [m_forwardingHint], nonce
  auto param = appendtlv::encodeAppendParameters(m_localPrefix, ndn::random::generateSecureWord64(), m_forwardingHint);
  notification.setApplicationParameters(param);

  // do we really need to sign notification interest? I don't think so?
  // m_keyChain.sign(notification);

  // ideally we need fill in all three callbacks
  m_face.expressInterest(notification, [this] (auto&&, const auto& i) { /* do sth? */}, nullptr, nullptr);
}

void
HandleClient::onCommandFetchingInterest(const Interest& interest)
{
  // Interest: /<m_prefix>/msg/<topic>/<nonce>
  // <topic> should be /<ct-prefix>/append

  const ssize_t NONCE_OFFSET = -1;
  uint64_t nonce = interest.getName().get(NONCE_OFFSET).toNumber();
  NDN_LOG_DEBUG("nonce = " << nonce);
  
  Data command(interest.getName());
  appendtlv::encodeAppendContent(m_dataName, m_forwardingHint);
  Block content(ndn::tlv::Content);

  // sign by identity key
  m_keyChain.sign(command, ndn::signingByIdentity(m_localPrefix));

  NDN_LOG_DEBUG(command);
  m_face.put(command);

  m_face.setInterestFilter(ndn::InterestFilter(m_data.getName()), [&] (auto&&, const auto& interest) { m_face.put(m_data); }, 
                           [this] (auto&&, const auto& reason) {
                             NDN_LOG_ERROR("Failed to register prefix in local hub's daemon, REASON: " << reason);
                           });
}


void
HandleClient::runAppend()
{
  if (m_data.getName().empty() || m_localPrefix.empty()) {
    NDN_LOG_ERROR("Cannot runAppend, neither dataName or reachable prefix is set\n");
  }

  // register reachable prefix to NFD
  auto prefixId = m_face.registerPrefix(
    m_localPrefix, 
    [&] (const Name& name) {
      // notice: this only register FIB to Face, not NFD.
      // register for m_data
      auto filterId = m_face.setInterestFilter(m_data.getName(), [this] (auto&&, const auto& i)  { m_face.put(m_data); });
      NDN_LOG_TRACE("Registering filter for m_data " << m_data.getName());

      // register for /<prefix>/msg
      filterId = m_face.setInterestFilter(Name(m_localPrefix).append("msg"), [this] (auto&&, const auto& i)
          { onCommandFetchingInterest(i); });
      NDN_LOG_TRACE("Registering filter for m_localPrefix/msg " << Name(m_localPrefix).append("msg"));
   },
   [this] (auto&&, const auto& reason) { onRegisterFailed(reason); });

   runNotify();
}

void
HandleClient::onRegisterFailed(const std::string& reason)
{
  NDN_LOG_ERROR("Failed to register prefix with the local forwarder (" << reason << ")\n");
  m_face.shutdown();
}

} // namespace append
} // namespace ndnrevoke

#include "append/client.hpp"

namespace ndnrevoke::append {
namespace tlv = appendtlv;

NDN_LOG_INIT(ndnrevoke.append);

const ssize_t MAX_RETRIES = 6;

Client::Client(const Name& prefix, ndn::Face& face, ndn::KeyChain& keyChain, ndn::security::Validator& validator)
  : m_face(face)
  , m_prefix(prefix)
  , m_keyChain(keyChain)
  , m_validator(validator)
{
  // register reachable prefix to NFD
  auto prefixId = m_face.registerPrefix(prefix, 
    [] (auto&&) {},
    [this] (auto&&, const auto& reason) {
      NDN_LOG_ERROR("Failed to register prefix with the local forwarder (" << reason << ")\n");
      m_face.shutdown();
    }
  );
  m_handle.handlePrefix(prefixId);
}

uint64_t
Client::appendData(const Name& topic, const std::list<Data>& data,
                   const onSuccessCallback successCb, const onFailureCallback failureCb,
                   const onTimeoutCallback timeoutCb, const onNackCallback nackCb)
{
  uint64_t nonce = ndn::random::generateSecureWord64();
  // auto state = std::make_shared<ClientState>(m_prefix, m_face, nonce, m_keyChain, m_validator);
  auto state = new ClientState(m_prefix, m_face, nonce, m_keyChain, m_validator);
  state->appendData(topic, data, successCb, failureCb, timeoutCb, nackCb);
  return nonce;
}

} // namespace ndnrevoke::append

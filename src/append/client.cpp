#include "append/client.hpp"

namespace ndnrevoke::append {
namespace tlv = appendtlv;

NDN_LOG_INIT(ndnrevoke.append);

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
                   const ClientOptions::onSuccessCallback successCb,
                   const ClientOptions::onFailureCallback failureCb)
{
  auto state = std::make_shared<ClientState>(m_prefix, m_face,
                                             m_keyChain, m_validator);
  return state->appendData(topic, data, successCb, failureCb);
}

} // namespace ndnrevoke::append

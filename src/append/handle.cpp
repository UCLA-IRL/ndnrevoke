#include "append/append-encoder.hpp"
#include "append/append-common.hpp"
#include "append/handle.hpp"

namespace ndnrevoke {
namespace append {

Handle::Handle(const Name& localPrefix, ndn::Face& face, ndn::KeyChain& keyChain)
  : m_localPrefix(localPrefix)
  , m_face(face)
  , m_keyChain(keyChain)
{
}

Handle::~Handle()
{
  for (auto& handle : m_interestFilterHandles) {
    handle.cancel();
  }
  for (auto& handle : m_registeredPrefixHandles) {
    handle.unregister();
  }
}

} // namespace append
} // namespace ndnrevoke

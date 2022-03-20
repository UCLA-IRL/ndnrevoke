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

} // namespace append
} // namespace ndnrevoke

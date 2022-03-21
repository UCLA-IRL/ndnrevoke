#ifndef NDNREVOKE_APPEND_HANDLE_HPP
#define NDNREVOKE_APPEND_HANDLE_HPP

#include "append/append-common.hpp"

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/face.hpp>

namespace ndnrevoke {
namespace append {

class Handle : boost::noncopyable
{
public:
  explicit
  Handle(const ndn::Name& prefix, ndn::Face& face, ndn::KeyChain& keyChain);

  ~Handle();

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PROTECTED:
  ndn::Name m_localPrefix;
  ndn::Face& m_face;
  ndn::KeyChain& m_keyChain;

  std::list<ndn::RegisteredPrefixHandle> m_registeredPrefixHandles;
  std::list<ndn::InterestFilterHandle> m_interestFilterHandles;
};

} // namespace append
} // namespace ndnrevoke

#endif // NDNREVOKE_APPEND_HANDLE_HPP

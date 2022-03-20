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

  void
  setForwardingHint(const ndn::Name& forwardingHint)
  {
    m_forwardingHint = forwardingHint;
  }

  void
  setNonce(const uint64_t nonce)
  {
    m_nonce = nonce;
  }

  ndn::Name&
  getForwardingHint()
  {
    return m_forwardingHint;
  }

  tlv::AppendStatus
  getStatusCode()
  {
    return m_statusCode;
  }

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PROTECTED:
  ndn::Name m_localPrefix;
  uint64_t m_nonce;
  ndn::Name m_dataName;
  ndn::Name m_forwardingHint;
  ndn::Face& m_face;
  ndn::KeyChain& m_keyChain;
  tlv::AppendStatus m_statusCode = tlv::AppendStatus::NOTINITIALIZED;
};

} // namespace append
} // namespace ndnrevoke

#endif // NDNREVOKE_APPEND_HANDLE_HPP

#ifndef NDNREVOKE_APPEND_CLIENT_STATE_HPP
#define NDNREVOKE_APPEND_CLIENT_STATE_HPP

#include "append/handle.hpp"
#include "append/options.hpp"
#include "error.hpp"

namespace ndnrevoke::append {

using onSuccessCallback = std::function<void(const Data&)>; // notification ack
using onFailureCallback = std::function<void(const std::list<Data>&, const Error&)>; // notification ack

class ClientState : boost::noncopyable
{
public:

  explicit
  ClientState(const Name& prefix, ndn::Face& face, uint64_t nonce,
              ndn::KeyChain& keyChain, ndn::security::Validator& validator);

  explicit
  ClientState(const Name& prefix, ndn::Face& face,
              uint64_t nonce, const Name& fwHint,
              ndn::KeyChain& keyChain, ndn::security::Validator& validator);

  void
  appendData(const Name& topic, const std::list<Data>& data,
             const onSuccessCallback successCb, const onFailureCallback failureCb);

  uint64_t
  getNonce() const
  {
    return m_options.getNonce();
  }

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  dispatchNotification(const std::list<Data>& data, Interest& interest);

  void
  onValidationSuccess(const Data& data);

  ssize_t m_retryCount = 0;
  ndn::Face& m_face;
  ClientOptions m_options;
  Handle m_handle;

  onSuccessCallback m_sCb;
  onFailureCallback m_fCb;

  ndn::KeyChain& m_keyChain;
  ndn::security::Validator& m_validator;
};

} // namespace ndnrevoke:append

#endif // NDNREVOKE_APPEND_CLIENT_STATE_HPP

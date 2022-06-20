#ifndef NDNREVOKE_APPEND_CLIENT_STATE_HPP
#define NDNREVOKE_APPEND_CLIENT_STATE_HPP

#include "append/handle.hpp"
#include "append/client-options.hpp"
#include "error.hpp"

namespace ndnrevoke::append {

class Client : boost::noncopyable
{
public:

  explicit
  Client(const Name& prefix, ndn::Face& face,
         ndn::KeyChain& keyChain, ndn::security::Validator& validator);

  explicit
  Client(const Name& prefix, ndn::Face& face,
         const Name& fwHint,
         ndn::KeyChain& keyChain, ndn::security::Validator& validator);

  uint64_t
  appendData(const Name& topic, const std::list<Data>& data,
             const ClientOptions::onSuccessCallback onSuccess,
             const ClientOptions::onFailureCallback onFailure);

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  dispatchNotification(const std::shared_ptr<ClientOptions>& options, const std::list<Data>& data);

  void
  onValidationSuccess(const std::shared_ptr<ClientOptions>& options, const std::list<Data>& data, const Data& ack);

  void
  onValidationFailure(const std::shared_ptr<ClientOptions>& options, const std::list<Data>& data,
                      const ndn::security::ValidationError& error);

  ssize_t m_retryCount = 0;
  ndn::Face& m_face;
  Name m_prefix;
  Handle m_handle;

  ndn::KeyChain& m_keyChain;
  ndn::security::Validator& m_validator;
};

} // namespace ndnrevoke:append

#endif // NDNREVOKE_APPEND_CLIENT_STATE_HPP

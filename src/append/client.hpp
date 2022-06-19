#ifndef NDNREVOKE_APPEND_CLIENT_HPP
#define NDNREVOKE_APPEND_CLIENT_HPP

#include "append/client-state.hpp"

namespace ndnrevoke::append {


class Client : boost::noncopyable
{
public:
  explicit
  Client(const Name& prefix, ndn::Face& face, ndn::KeyChain& keyChain, ndn::security::Validator& validator);

  std::shared_ptr<ClientState>
  appendData(const Name& topic, const std::list<Data>& data,
             const onSuccessCallback successCb, const onFailureCallback failureCb);

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  ndn::Face& m_face;
  Name m_prefix;
  Handle m_handle;
  ndn::KeyChain& m_keyChain;
  ndn::security::Validator& m_validator;
};

} // namespace ndnrevoke:append

#endif // NDNREVOKE_APPEND_CLIENT_HPP

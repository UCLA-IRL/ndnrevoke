#ifndef NDNREVOKE_APPEND_HANDLE_CT_STATE_HPP
#define NDNREVOKE_APPEND_HANDLE_CT_STATE_HPP

#include "append/options.hpp"
#include "append/handle.hpp"

namespace ndnrevoke::append {
using appendtlv::AppendStatus;

using UpdateCallback = std::function<AppendStatus(const Data&)>;

class CtState : boost::noncopyable
{
public:
  explicit
  CtState(const Name& prefix, const Name& topic, ndn::Face& face, 
          ndn::KeyChain& keyChain, ndn::security::Validator& validator);

  void
  listen(const UpdateCallback& onUpdateCallback);

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  serveClient(std::shared_ptr<ClientOptions> client);

  void
  onValidationSuccess(const Data& data, std::shared_ptr<ClientOptions> client);

  void
  onValidationFailure(const Data& data, const ndn::security::ValidationError& error,
                      std::shared_ptr<ClientOptions> client);

  Name m_prefix;
  ndn::Face& m_face;
  Name m_topic;
  CtOptions m_options{m_topic};
  ssize_t m_retryCount = 0;

  UpdateCallback m_onUpdate;
  Handle m_handle;

  ndn::KeyChain& m_keyChain;
  ndn::security::Validator& m_validator;

  bool m_isDone = false;
};

} // namespace ndnrevoke:append

#endif // NDNREVOKE_APPEND_HANDLE_CT_STATE_HPP

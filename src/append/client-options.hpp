#ifndef NDNREVOKE_APPEND_CLIENT_OPTIONS_HPP
#define NDNREVOKE_APPEND_CLIENT_OPTIONS_HPP

#include "append-common.hpp"
#include "error.hpp"

namespace ndnrevoke::append {
using appendtlv::AppendStatus;

class ClientOptions : boost::noncopyable
{
public:
  const ssize_t MAX_RETRIES = 3;

  using onSuccessCallback = std::function<void(const std::list<Data>&, const Data&)>; // notification ack
  using onFailureCallback = std::function<void(const std::list<Data>&, const Error&)>; // notification ack

  explicit
  ClientOptions(const Name& prefix, const Name& topic, uint64_t nonce,
                const onSuccessCallback onSuccess, const onFailureCallback onFailure)
  : m_topic(topic)
  , m_prefix(prefix)
  , m_nonce(nonce)
  , m_sCb(onSuccess)
  , m_fCb(onFailure)
  {
  }

  explicit
  ClientOptions(const Name& prefix, const Name& topic, uint64_t nonce,
                const onSuccessCallback onSuccess, const onFailureCallback onFailure,
                const Name& fwHint)
  : m_topic(topic)
  , m_prefix(prefix)
  , m_nonce(nonce)
  , m_sCb(onSuccess)
  , m_fCb(onFailure)
  , m_fwHint(fwHint)
  {
  }

  const Name&
  getForwardingHint() const
  {
    return m_fwHint; 
  }

  const Name
  getPrefix() const
  {
    return m_prefix; 
  }

  uint64_t
  getNonce() const
  {
    return m_nonce;
  }

  bool
  exhaustRetries()
  {
    return m_retryCount++ > MAX_RETRIES? true : false;
  }

  std::shared_ptr<Interest>
  makeNotification();

  const Name
  makeInterestFilter();

  std::shared_ptr<Interest>
  makeFetcher();

  std::shared_ptr<Data>
  makeSubmission(const std::list<Data>& dataList);

  std::shared_ptr<Data>
  makeNotificationAck(const std::list<AppendStatus>& statusList);

  std::list<AppendStatus>
  praseAck(const Data& data); 

  void
  onSuccess(const std::list<Data>& data, const Data& ack)
  {
    return m_sCb(data, ack);
  }

  void
  onFailure(const std::list<Data>& data, const Error& error)
  {
    return m_fCb(data, error);
  }

private:
  Name m_topic;
  Name m_prefix;
  uint64_t m_nonce;
  ssize_t m_retryCount = 0;

  onSuccessCallback m_sCb;
  onFailureCallback m_fCb;
  Name m_fwHint;
};

} // namespace ndnrevoke:append

#endif // NDNREVOKE_APPEND_CLIENT_OPTIONS_HPP

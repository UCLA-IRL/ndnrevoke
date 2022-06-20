#ifndef NDNREVOKE_APPEND_OPTIONS_HPP
#define NDNREVOKE_APPEND_OPTIONS_HPP

#include "append/handle.hpp"
#include "error.hpp"

namespace ndnrevoke::append {
using appendtlv::AppendStatus;

class BaseOptions
{
public:
  explicit
  BaseOptions(const Name& prefix, uint64_t nonce)
    : m_prefix(prefix)
    , m_nonce(nonce)
  {
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

private:
  Name m_prefix;
  uint64_t m_nonce;
};

class ClientOptions : public BaseOptions
{
public:

  using onSuccessCallback = std::function<void(const std::list<Data>&, const Data&)>; // notification ack
  using onFailureCallback = std::function<void(const std::list<Data>&, const Error&)>; // notification ack

  explicit
  ClientOptions(const Name& prefix, const Name& topic, uint64_t nonce,
                const onSuccessCallback onSuccess, const onFailureCallback onFailure)
  : BaseOptions(prefix, nonce)
  , m_topic(topic)
  , m_sCb(onSuccess)
  , m_fCb(onFailure)
  {
  }

  explicit
  ClientOptions(const Name& prefix, const Name& topic, uint64_t nonce,
                const onSuccessCallback onSuccess, const onFailureCallback onFailure,
                const Name& fwHint)
  : BaseOptions(prefix, nonce)
  , m_topic(topic)
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
  onSuccessCallback m_sCb;
  onFailureCallback m_fCb;
  Name m_fwHint;
};

class CtOptions : boost::noncopyable
{
public:
  explicit
  CtOptions(const Name& topic)
  : m_topic(topic)
  {
  }

  std::shared_ptr<ClientOptions>
  praseNotification(const Interest& notification); 

  std::shared_ptr<Interest>
  makeFetcher(ClientOptions& client);

  std::shared_ptr<Data>
  makeNotificationAck(ClientOptions& client,
                      const std::list<AppendStatus>& statusList);

private:
  Name m_topic;
};

} // namespace ndnrevoke:append

#endif // NDNREVOKE_APPEND_OPTIONS_HPP

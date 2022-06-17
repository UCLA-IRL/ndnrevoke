#ifndef NDNREVOKE_APPEND_OPTIONS_HPP
#define NDNREVOKE_APPEND_OPTIONS_HPP

#include "append/handle.hpp"

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
  explicit
  ClientOptions(const Name& prefix, uint64_t nonce)
  : BaseOptions(prefix, nonce)
  {
  }

  explicit
  ClientOptions(const Name& prefix, uint64_t nonce, const Name& fwHint)
  : BaseOptions(prefix, nonce)
  , m_fwHint(fwHint)
  {
  }

  const Name&
  getForwardingHint() const
  {
    return m_fwHint; 
  }

  std::shared_ptr<Interest>
  makeNotification(const Name& topic);

  const Name
  makeInterestFilter(const Name& topic);

  std::shared_ptr<Interest>
  makeFetcher(const Name& topic);

  std::shared_ptr<Data>
  makeSubmission(const Name& topic, const std::list<Data>& dataList);

  std::shared_ptr<Data>
  makeNotificationAck(const Name& topic, const std::list<AppendStatus>& statusList);

  std::list<AppendStatus>
  praseAck(const Data& data); 

private:
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

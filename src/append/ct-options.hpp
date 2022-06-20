#ifndef NDNREVOKE_APPEND_CT_OPTIONS_HPP
#define NDNREVOKE_APPEND_CT_OPTIONS_HPP

#include "append/client-options.hpp"

namespace ndnrevoke::append {
using appendtlv::AppendStatus;

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

#endif // NDNREVOKE_APPEND_CT_OPTIONS_HPP

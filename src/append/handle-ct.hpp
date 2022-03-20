#ifndef NDNREVOKE_APPEND_HANDLE_CT_HPP
#define NDNREVOKE_APPEND_HANDLE_CT_HPP

#include "append/append-common.hpp"
#include "append/append-encoder.hpp"
#include "append/handle.hpp"

namespace ndnrevoke {
namespace append {

using UpdateCallback = std::function<void(const Data&)>;


class HandleCt : public Handle
{
public:
  explicit
  HandleCt(const ndn::Name& prefix, ndn::Face& face, ndn::KeyChain& keyChain);
  
  void
  listenOnTopic(Name& topic, const UpdateCallback& onUpdateCallback);
NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  onNotification(Interest interest);

  void
  onCommandData(Data data);

  void
  onData(Data data);

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::map<uint64_t, appendtlv::AppenderInfo> m_nonceMap;
  Name m_topic;

   /**
   * Update Callback function
   */
  UpdateCallback m_updateCallback;
};

} // namespace append
} // namespace ndnrevoke

#endif // NDNREVOKE_APPEND_HANDLE_CLIENT_HPP
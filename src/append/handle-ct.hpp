#ifndef NDNREVOKE_APPEND_HANDLE_CT_HPP
#define NDNREVOKE_APPEND_HANDLE_CT_HPP

#include "append/append-common.hpp"
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
  setTopic(const ndn::Name& topic)
  {
    m_topic = topic;
  }
  
  void
  addNonce(const uint64_t nonce)
  { 
    m_nonceMap.insert({nonce, Name()});
  }

  void
  addNonce(const uint64_t nonce, const Name& remotePrefix)
  { 
    m_nonceMap.insert({nonce, remotePrefix});
  }

  std::map<uint64_t, ndn::Name>::iterator
  findNonce(const uint64_t nonce)
  { 
    return m_nonceMap.find(nonce);
  }

  void
  updateNonce(uint64_t nonce, Name& remotePrefix)
  { 
    auto it = m_nonceMap.find(nonce);
    if (it != m_nonceMap.end()) {
      it->second = remotePrefix;
    }
  }

  void
  deleteNonce(uint64_t nonce)
  { 
    auto it = m_nonceMap.find(nonce);
    if (it != m_nonceMap.end()) {
      m_nonceMap.erase(it);
    }
  }

  void
  setUpdateCallback(const UpdateCallback& onUpdateCallback)
  {
    m_updateCallback = onUpdateCallback;
  }

  void
  listenOnTopic(Name& topic);
NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  onNotification(Interest interest);

  void
  onCommandData(Data data);

  void
  onData(Data data);

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::map<uint64_t, Name> m_nonceMap;
  Data m_data;
  Name m_dataName;
  Name m_topic;

   /**
   * Update Callback function
   */
  UpdateCallback m_updateCallback;
};

} // namespace append
} // namespace ndnrevoke

#endif // NDNREVOKE_APPEND_HANDLE_CLIENT_HPP

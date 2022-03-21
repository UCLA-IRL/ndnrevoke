#ifndef NDNREVOKE_APPEND_HANDLE_CLIENT_HPP
#define NDNREVOKE_APPEND_HANDLE_CLIENT_HPP

#include "append/append-common.hpp"
#include "append/handle.hpp"

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/face.hpp>

namespace ndnrevoke {
namespace append {

using onSuccessCallback = std::function<void(const Data&)>; // notification ack
using onFailureCallback = std::function<void(const Data&)>; // notification ack
using onTimeoutCallback = std::function<void(const Interest&)>; // notification interest

struct AppendCallBack {
  onSuccessCallback onSuccess;
  onFailureCallback onFailure;
  onTimeoutCallback onTimeout;
};

class HandleClient : public Handle
{
public:
  explicit
  HandleClient(const ndn::Name& prefix, ndn::Face& face, ndn::KeyChain& keyChain);

  void
  appendData(const ndn::Name& topic, Data& data);

  void
  appendData(const ndn::Name& topic, Data& data, const onSuccessCallback successCb, 
             const onFailureCallback failureCb, const onTimeoutCallback timeoutCb);

  void
  setForwardingHint(const Name& forwardingHint)
  {
    m_forwardingHint = forwardingHint;
  }
  
NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:

  std::shared_ptr<Interest>
  makeNotification(const ndn::Name& topic, uint64_t nonce);

  void
  onNotificationAck(const uint64_t nonce, const Data& data);

  void
  onDataFetchingInterest(const ndn::InterestFilter&, const Interest& interest);

  void
  onCommandFetchingInterest(const Interest& interest);

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  Name m_forwardingHint;
  std::map<uint64_t, Data> m_nonceMap;
  std::map<uint64_t, AppendCallBack> m_callback;
};

} // namespace append
} // namespace ndnrevoke

#endif // NDNREVOKE_APPEND_HANDLE_CLIENT_HPP

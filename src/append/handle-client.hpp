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
using onNackCallback = std::function<void(const Interest&, const ndn::lp::Nack& nack)>; // nack

struct AppendCallBack {
  onSuccessCallback onSuccess;
  onFailureCallback onFailure;
  onTimeoutCallback onTimeout;
  onNackCallback onNack;
};

class HandleClient : public Handle
{
public:
  explicit
  HandleClient(const ndn::Name& prefix, ndn::Face& face, ndn::KeyChain& keyChain);

  uint64_t
  appendData(const ndn::Name& topic, std::list<Data> data);

  uint64_t
  appendData(const ndn::Name& topic, std::list<Data> data, const onSuccessCallback successCb, 
             const onFailureCallback failureCb, const onTimeoutCallback timeoutCb, const onNackCallback nackCb);

  void
  setForwardingHint(const Name& forwardingHint)
  {
    m_forwardingHint = forwardingHint;
  }
  
NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  dispatchNotification(const Interest& interest, uint64_t nonce);

  std::shared_ptr<Interest>
  makeNotification(const ndn::Name& topic, uint64_t nonce);

  void
  onNotificationAck(const uint64_t nonce, const Data& data);

  void
  onDataFetchingInterest(const ndn::InterestFilter&, const Interest& interest);

  void
  onSubmissionFetchingInterest(const Interest& interest);

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  Name m_forwardingHint;
  // this number is shared by all append operations, and reset each time receving notification ack
  ssize_t m_retryCount = 0;
  std::unordered_map<uint64_t, std::list<Data>> m_nonceMap;
  std::unordered_map<uint64_t, AppendCallBack> m_callback;
};

} // namespace append
} // namespace ndnrevoke

#endif // NDNREVOKE_APPEND_HANDLE_CLIENT_HPP

#ifndef NDNREVOKE_APPEND_HANDLE_CLIENT_HPP
#define NDNREVOKE_APPEND_HANDLE_CLIENT_HPP

#include "append/append-common.hpp"
#include "append/handle.hpp"

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/face.hpp>

namespace ndnrevoke {
namespace append {

class HandleClient : public Handle
{
public:
  explicit
  HandleClient(const ndn::Name& prefix, ndn::Face& face, ndn::KeyChain& keyChain);

  void
  appendData(const ndn::Name& topic, Data& data);

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:

  void
  runNotify(const ndn::Name& topic, uint64_t nonce, Data data);

  void
  onNotificationAck(const Data& data);


  void
  onDataFetchingInterest(const ndn::InterestFilter&, const Interest& interest);

  void
  onCommandFetchingInterest(const Interest& interest);

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::map<uint64_t, Data> m_nonceMap;
};

} // namespace append
} // namespace ndnrevoke

#endif // NDNREVOKE_APPEND_HANDLE_CLIENT_HPP

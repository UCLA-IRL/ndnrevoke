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

  void
  setData(Data& data)
  {
    m_data = data;
  }

  Data&
  getData()
  {
    return m_data;
  }
  
  void
  setRemotePrefix(const ndn::Name& remotePrefix)
  {
    m_remotePrefix = remotePrefix;
  }
  
  void
  runAppend();
NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:

  void
  runNotify();

  void
  onDataFetchingInterest(const ndn::InterestFilter&, const Interest& interest);

  void
  onCommandFetchingInterest(const Interest& interest);

  void
  onRegisterFailed(const std::string& reason);
NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  ndn::Name m_remotePrefix;
  Data m_data;
};

} // namespace append
} // namespace ndnrevoke

#endif // NDNREVOKE_APPEND_HANDLE_CLIENT_HPP

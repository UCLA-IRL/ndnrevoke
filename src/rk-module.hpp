#ifndef NDNREVOKE_RK_MODULE_HPP
#define NDNREVOKE_RK_MODULE_HPP

#include "rk-storage.hpp"
#include "rk-configuration.hpp"
#include "nack.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>

namespace ndnrevoke {
namespace rk {

class RkModule : boost::noncopyable
{
public:
  RkModule(ndn::Face& face, ndn::KeyChain& keyChain, const std::string& configPath,
           const std::string& storageType = "ca-storage-memory");

  ~RkModule();

  const std::unique_ptr<RkStorage>&
  getRkStorage()
  {
    return m_storage;
  }

  RkConfig&
  getRkConf()
  {
    return m_config;
  }

  void
  onQuery(const Interest& query);

  std::unique_ptr<RevocationState>
  getRevocationState(const Name& certName);

private:
  std::shared_ptr<nack::Nack>
  prepareNack(const RevocationState& revocationState, Name::Component publisherId, 
              ndn::time::milliseconds freshnessPeriod = 10_h);

  void
  registerPrefix();

  void
  onRegisterFailed(const std::string& reason);

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  ndn::Face& m_face;
  RkConfig m_config;
  ndn::KeyChain& m_keyChain;
  std::unique_ptr<RkStorage> m_storage;
  std::list<ndn::RegisteredPrefixHandle> m_registeredPrefixHandles;
  std::list<ndn::InterestFilterHandle> m_interestFilterHandles;
};

} // namespace rk
} // namespace ndnrevoke

#endif // NDNREVOKE_RK_MODULE_HPP

#ifndef NDNREVOKE_CT_MODULE_HPP
#define NDNREVOKE_CT_MODULE_HPP

#include "ct-storage.hpp"
#include "ct-configuration.hpp"
#include "nack.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>

namespace ndnrevoke {
namespace ct {

class CtModule : boost::noncopyable
{
public:
  CtModule(ndn::Face& face, ndn::KeyChain& keyChain, const std::string& configPath,
           const std::string& storageType = "ct-storage-memory");

  ~CtModule();

  const std::unique_ptr<CtStorage>&
  getCtStorage()
  {
    return m_storage;
  }

  CtConfig&
  getCtConf()
  {
    return m_config;
  }

  void
  onQuery(const Interest& query);

  std::unique_ptr<CertificateState>
  getCertificateState(const Name& certName);

private:
  std::shared_ptr<nack::Nack>
  prepareNack(const CertificateState& certState, Name::Component publisherId, 
              ndn::time::milliseconds freshnessPeriod = 10_h);

  void
  registerPrefix();

  void
  onRegisterFailed(const std::string& reason);

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  ndn::Face& m_face;
  CtConfig m_config;
  ndn::KeyChain& m_keyChain;
  std::unique_ptr<CtStorage> m_storage;
  std::list<ndn::RegisteredPrefixHandle> m_registeredPrefixHandles;
  std::list<ndn::InterestFilterHandle> m_interestFilterHandles;
};

} // namespace ct
} // namespace ndnrevoke

#endif // NDNREVOKE_CT_MODULE_HPP

#ifndef NDNREVOKE_CT_MODULE_HPP
#define NDNREVOKE_CT_MODULE_HPP

#include "storage/ct-storage.hpp"
#include "append/handle.hpp"
#include "append/ct-state.hpp"
#include "ct-configuration.hpp"
#include "nack.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/validator-config.hpp>

namespace ndnrevoke::ct {
using appendtlv::AppendStatus;

class CtModule : boost::noncopyable
{
public:
  CtModule(ndn::Face& face, ndn::KeyChain& keyChain, const std::string& configPath,
           const std::string& storageType = "ct-storage-memory");

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


NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:

  AppendStatus onDataSubmission(const Data& data);

  void
  registerPrefix();

  void
  onRegisterFailed(const std::string& reason);

  bool
  isValidQuery(Name queryName);

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  ndn::Face& m_face;
  CtConfig m_config;
  ndn::KeyChain& m_keyChain;
  ndn::ValidatorConfig m_validator{m_face};
  std::unique_ptr<CtStorage> m_storage;

  append::Handle m_handle;
};

} // namespace ndnrevoke::ct

#endif // NDNREVOKE_CT_MODULE_HPP

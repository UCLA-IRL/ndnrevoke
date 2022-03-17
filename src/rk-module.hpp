#ifndef NDNREVOKE_RK_MODULE_HPP
#define NDNREVOKE_RK_MODULE_HPP

#include "rk-storage.hpp"
#include "nack.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>

namespace ndnrevoke {
namespace rk {

class RkModule : boost::noncopyable
{
public:
  RkModule(ndn::Face& face, ndn::KeyChain& keyChain, Name& rkPrefix,
           const std::string& storageType = "ca-storage-memory");

  ~RkModule();

  const std::unique_ptr<RkStorage>&
  getRkStorage()
  {
    return m_storage;
  }

  void
  onQuery(const Interest& query);

  std::unique_ptr<RevocationState>
  getRevocationState(const Name& certName);

private:

  std::shared_ptr<nack::Nack>
  getNack(const RevocationState& revocationState);

  void
  registerPrefix();

  void
  onRegisterFailed(const std::string& reason);

  ndn::Face& m_face;
  Name m_rkPrefix;
  // operator should list the namespace(s) that this RK is responsible of.
  // RK won't do look up for records that are that belong to any of the record Zone.
  // no protocol side impact, purely for filtering RK side unnecessary record look up.
  std::vector<Name> m_recordZone;
  std::unique_ptr<RkStorage> m_storage;
  ndn::KeyChain& m_keyChain;

  std::list<ndn::RegisteredPrefixHandle> m_registeredPrefixHandles;
  std::list<ndn::InterestFilterHandle> m_interestFilterHandles;
};

} // namespace rk
} // namespace ndnrevoke

#endif // NDNREVOKE_RK_MODULE_HPP

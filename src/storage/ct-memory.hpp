#ifndef NDNREVOKE_CT_MEMORY_HPP
#define NDNREVOKE_CT_MEMORY_HPP

#include "ct-storage.hpp"

namespace ndnrevoke {
namespace ct {

class CtMemory : public CtStorage
{
public:
  CtMemory(ndn::security::KeyChain& keychain, const Name& ctName = Name(), const std::string& path = "");
  const static std::string STORAGE_TYPE;

public:
  /**
   * @throw if certificate state cannot be fetched from underlying data storage
   */
  CertificateState
  getCertificateState(const Name& certName) override;

  /**
   * @throw if there is an existing RevocationState with the same certName
   */
  void
  addCertificateState(const CertificateState& state) override;

  void
  updateCertificateState(const CertificateState& state) override;

  void
  deleteCertificateState(const Name& certName) override;

  std::list<CertificateState>
  listAllCertificateStates() override;

  std::list<CertificateState>
  listAllCertificateStates(const Name& ctName) override;

private:
  std::map<std::string, CertificateState> m_certStates;
};

} // namespace ct
} // namespace ndnrevoke

#endif // NDNREVOKE_CT_MEMORY_HPP

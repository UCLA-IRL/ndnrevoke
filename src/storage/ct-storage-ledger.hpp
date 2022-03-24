//
// Created by Tyler on 3/23/22.
//

#ifndef NDNREVOKE_CT_STORAGE_LEDGER_HPP
#define NDNREVOKE_CT_STORAGE_LEDGER_HPP

#include "ct-storage.hpp"
#include "cert-ledger/cert-ledger.hpp"

namespace ndnrevoke {
namespace ct {

class CtStorageLedger : public CtStorage {
  public:
    CtStorageLedger(const Name& ctName = Name(), const std::string& path = "");
    CtStorageLedger(const cert_ledger::Config &config,
                    security::KeyChain &keychain,
                    Face &network,
                    std::shared_ptr<ndn::security::Validator> recordValidator);
    const static std::string STORAGE_TYPE;
  public:
    CertificateState getCertificateState(const Name &certName) override;

    void addCertificateState(const CertificateState &state) override;

    void updateCertificateState(const CertificateState &state) override;

    void deleteCertificateState(const Name &certName) override;

    std::list<CertificateState> listAllCertificateStates() override;

    std::list<CertificateState> listAllCertificateStates(const Name &ctName) override;

  private:
    std::unique_ptr<cert_ledger::CertLedger> m_ledger;
};

} // namespace ct
} // namespace ndnrevoke


#endif //NDNREVOKE_CT_STORAGE_LEDGER_HPP

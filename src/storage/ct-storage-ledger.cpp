//
// Created by Tyler on 3/23/22.
//

#include "ct-storage-ledger.hpp"
#include "record-encoder.hpp"

#include "ndn-cxx/security/validator-config.hpp"
#include <string>

namespace ndnrevoke {
namespace ct {

NDN_LOG_INIT(ndnrevoke.ct-storage.ledger);

const std::string CtStorageLedger::STORAGE_TYPE = "ct-storage-ledger";
NDNREVOKE_REGISTER_CT_STORAGE(CtStorageLedger);

CtStorageLedger::CtStorageLedger(const Name& ctName, const std::string& path) {
    std::string dbPath;
    if (path.empty())
        dbPath = "/tmp/cert-ledger-db/" + readString(ctName.get(-1));
    else
        dbPath = path;
    Face face;
    security::KeyChain keychain;
    std::shared_ptr<cert_ledger::Config> config = nullptr;
    std::shared_ptr<ndn::security::Validator> validator;
    try {
        config = cert_ledger::Config::CustomizedConfig("/ndn/broadcast/cert-ledger-dag", "/ndn/broadcast/cert-ledger", ctName.toUri(),
                                                       dbPath);
        auto configValidator = std::make_shared<ndn::security::ValidatorConfig>(face);
        configValidator->load("./test/loggers.schema");
        validator = configValidator;
    }
    catch (const std::exception &e) {
        NDN_LOG_ERROR("error at initializing ledger storage: " << e.what());
        NDN_THROW(e);
    }
    m_ledger = std::make_unique<cert_ledger::CertLedger>(*config, keychain, face, validator);
}

CtStorageLedger::CtStorageLedger(const cert_ledger::Config &config,
                                 security::KeyChain &keychain,
                                 Face &network,
                                 std::shared_ptr<ndn::security::Validator> recordValidator)
        : m_ledger(std::make_unique<cert_ledger::CertLedger>(config, keychain, network, recordValidator))
{
}

CertificateState CtStorageLedger::getCertificateState(const ndn::Name &certName) {
    auto certRecord = m_ledger->getRecord(certName);
    auto revokeRecords = m_ledger->listRecord(record::Record::getRevocationRecordPrefix(certName));
    CertificateState state;
    state.cert = ndn::security::Certificate(certRecord->getContentItem());
    if (!certRecord) {
        state.status = CertificateStatus::NOTINITIALIZED;
        return state;
    }
    state.ctPrefix = certRecord->getProducerPrefix();
    if (revokeRecords.empty()) {
        state.status = CertificateStatus::VALID_CERTIFICATE;
        return state;
    } else {
        state.status = CertificateStatus::REVOKED_CERTIFICATE;
        state.record = record::Record(m_ledger->getRecord(*revokeRecords.begin())->getContentItem());

        return state;
    }
}

void CtStorageLedger::addCertificateState(const CertificateState &state) {
    NDN_LOG_TRACE("Adding CertificateState:\n" << state);
    if (m_ledger->hasRecord(state.cert.getName())) {
        NDN_THROW(std::runtime_error("Certificate State " + state.cert.getName().toUri() +
                                     " already exists"));
        return;
    }
    cert_ledger::Record r(m_ledger->getPeerPrefix(), state.cert);
    m_ledger->createRecord(r);
    if (state.status == CertificateStatus::REVOKED_CERTIFICATE)
        updateCertificateState(state);
}

void CtStorageLedger::updateCertificateState(const CertificateState &state) {
    auto revokeRecords = m_ledger->listRecord(record::Record::getRevocationRecordPrefix(state.cert.getName()));
    if (revokeRecords.empty() && state.status == CertificateStatus::REVOKED_CERTIFICATE) {
        cert_ledger::Record r(m_ledger->getPeerPrefix(), state.record);
        m_ledger->createRecord(r);
    } else {
        NDN_LOG_ERROR("Error on calling updateCertificateState: "
                      "ledger does not support modification other than add revocation");
    }
}

void CtStorageLedger::deleteCertificateState(const ndn::Name &certName) {
    NDN_LOG_ERROR("Error on calling deleteCertificateState: ledger does not support deletion");
}

std::list<CertificateState> CtStorageLedger::listAllCertificateStates() {
    return listAllCertificateStates(Name());
}

std::list<CertificateState> CtStorageLedger::listAllCertificateStates(const ndn::Name &ctName) {
    std::list<CertificateState> list;
    for (const auto& n : m_ledger->listRecord(ctName)) {
        if (readString(n.get(record::Record::REVOKE_OFFSET)) == "KEY") {
            list.emplace_back(getCertificateState(n));
        }
    }
    return list;
}

} // namespace ct
} // namespace ndnrevoke

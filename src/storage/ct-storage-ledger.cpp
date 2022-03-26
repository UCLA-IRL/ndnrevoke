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
        config = cert_ledger::Config::CustomizedConfig("/ndn/broadcast/cert-ledger-dag", ctName.toUri(),
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
    if (!certRecord) {
        CertificateState state;
        state.status = CertificateStatus::NOTINITIALIZED;
        return state;
    }
    auto state = makeCertificateState(ndn::security::Certificate(certRecord->getContentItem()));
    state->ctPrefix = certRecord->getProducerPrefix();
    if (revokeRecords.empty()) {
        state->status = CertificateStatus::VALID_CERTIFICATE;
        return *state;
    } else {
        state->status = CertificateStatus::REVOKED_CERTIFICATE;
        state->record = record::Record(m_ledger->getRecord(*revokeRecords.begin())->getContentItem());
        state->updateCertificateState(state->record);
        return *state;
    }
}

void CtStorageLedger::addCertificateState(const CertificateState &state) {
    NDN_LOG_TRACE("Adding CertificateState:\n" << state);
    if (state.ctPrefix != m_ledger->getPeerPrefix()) {
        NDN_THROW(std::runtime_error("This Ledger is not authoritative to the state"));
    }
    if (m_ledger->hasRecord(state.cert.getName())) {
        NDN_THROW(std::runtime_error("Certificate State " + state.cert.getName().toUri() +
                                     " already exists"));
    }
    cert_ledger::Record r(m_ledger->getPeerPrefix(), state.cert);
    auto code = m_ledger->createRecord(r);
    if (!code.success()) {
        NDN_THROW(std::runtime_error(code.what()));
    }
    if (state.status == CertificateStatus::REVOKED_CERTIFICATE)
        updateCertificateState(state);
}

void CtStorageLedger::updateCertificateState(const CertificateState &state) {
    auto revokeRecords = m_ledger->listRecord(record::Record::getRevocationRecordPrefix(state.cert.getName()));
    if (revokeRecords.empty() && state.status == CertificateStatus::REVOKED_CERTIFICATE) {
        cert_ledger::Record r(m_ledger->getPeerPrefix(), state.record);
        auto code = m_ledger->createRecord(r);
        if (!code.success()) {
            NDN_THROW(std::runtime_error(code.what()));
        }
    } else {
        NDN_LOG_ERROR("Error on calling updateCertificateState: "
                      "ledger does not support modification other than add revocation");
    }
}

void CtStorageLedger::deleteCertificateState(const ndn::Name &certName) {
    NDN_THROW(std::runtime_error("Error on calling deleteCertificateState: ledger does not support deletion"));
}

std::list<CertificateState> CtStorageLedger::listAllCertificateStates() {
    return listAllCertificateStates(Name());
}

std::list<CertificateState> CtStorageLedger::listAllCertificateStates(const ndn::Name &ctName) {
    std::list<CertificateState> list;
    for (const auto& n: m_ledger->listRecord(ctName)) {
        NDN_LOG_DEBUG(n);
    }
    for (const auto& n : m_ledger->listRecord(ctName)) {
        if (security::Certificate::isValidName(n)) {
            list.emplace_back(getCertificateState(n));
        }
    }
    return list;
}

} // namespace ct
} // namespace ndnrevoke

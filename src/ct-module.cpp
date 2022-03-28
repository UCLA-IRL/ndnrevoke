#include "ct-module.hpp"
#include "record-encoder.hpp"
#include "nack-encoder.hpp"
#include "state.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/util/string-helper.hpp>

namespace ndnrevoke {
namespace ct {

NDN_LOG_INIT(ndnrevoke.ct);

CtModule::CtModule(ndn::Face& face, ndn::KeyChain& keyChain, const std::string& configPath, const std::string& storageType)
  : m_face(face)
  , m_keyChain(keyChain)
{
  // load the config and create storage
  m_config.load(configPath);
  m_storage = CtStorage::createCtStorage(storageType, m_config.ctPrefix, "");
  registerPrefix();

  m_handle = std::make_shared<append::HandleCt>(m_config.ctPrefix, face, m_keyChain);
  m_handle->listenOnTopic(Name(m_config.ctPrefix).append("append"), std::bind(&CtModule::onDataSubmission, this, _1));
}

CtModule::~CtModule()
{
  for (auto& handle : m_interestFilterHandles) {
    handle.cancel();
  }
  for (auto& handle : m_registeredPrefixHandles) {
    handle.unregister();
  }
}

void
CtModule::registerPrefix()
{
  // register prefixes
  Name prefix = m_config.ctPrefix;
  // let's first use "CT" in protocol
  prefix.append("CT");

  auto prefixId = m_face.registerPrefix(
    prefix,
    [&] (const Name& name) {
      // register for each record Zone
      // notice: this only register FIB to Face, not NFD.
      for (auto& zone : m_config.recordZones) {
        auto filterId = m_face.setInterestFilter(zone, [this] (auto&&, const auto& i) { onQuery(i); });
        NDN_LOG_TRACE("Registering filter for recordZone " << zone);
        m_interestFilterHandles.push_back(filterId);
      }

      // register for submission
      auto filterId = m_face.setInterestFilter(Name(name).append("submit"), [this] (auto&&, const auto& i) { onSubmission(i); });
      NDN_LOG_TRACE("Registering filter for submission " << Name(name).append("submit"));
      m_interestFilterHandles.push_back(filterId);
    },
    [this] (auto&&, const auto& reason) { onRegisterFailed(reason); });
  m_registeredPrefixHandles.push_back(prefixId);
}

std::unique_ptr<CertificateState>
CtModule::getCertificateState(const Name& certName)
{
  try {
    return std::make_unique<CertificateState>(m_storage->getCertificateState(certName));
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Cannot get certificate state record from the storage\n");
    return nullptr;
  }
}

tlv::AppendStatus 
CtModule::onDataSubmission(const Data& data)
{
  NDN_LOG_TRACE("Received Submission " << data);
  if (data.getName().at(Certificate::KEY_COMPONENT_OFFSET) == Name::Component("KEY")) {
    Certificate cert(data);
    auto certState = makeCertificateState(cert);
    try {
      m_storage->addCertificateState(*certState);
    }
    catch (const std::exception& e) {
      m_storage->updateCertificateState(*certState);
    }
    return tlv::AppendStatus::SUCCESS;
  }
  else if (data.getName().at(record::Record::REVOKE_OFFSET) == Name::Component("REVOKE")) {
    record::Record record(data);
    CertificateState certState;
    try {
      certState = m_storage->getCertificateState(record.getCertificateName(record.getName()));
      certState.updateCertificateState(record);
      m_storage->updateCertificateState(certState);
      return tlv::AppendStatus::SUCCESS;
    }
    catch (const std::exception& e) {
      return tlv::AppendStatus::FAILURE_NX_CERT;
      // certState.updateCertificateState(record);
      // m_storage->addCertificateState(certState);
    }
  }
  return tlv::AppendStatus::NOTINITIALIZED;
}

void
CtModule::onSubmission(const Interest& submission)
{
  // Naming Convention: /<CT prefix>/CT/submit/<type>/<paramDigest>/
  // need to validate submission format
  NDN_LOG_TRACE("Received Submission " << submission);

  uint64_t statusCode = 1;
  const uint32_t submissionStatusType = 211U;
  const ssize_t submissionTypeOffset = -4;
  auto submissionType = submission.getName().at(submissionTypeOffset).toUri();
  if (submissionType == "cert") {
    auto paramBlock = submission.getApplicationParameters().blockFromValue();
    Certificate cert(paramBlock);
    auto certState = makeCertificateState(cert);
    try {
      m_storage->addCertificateState(*certState);
    }
    catch (const std::exception& e) {
      m_storage->updateCertificateState(*certState);
    }
  }
  else if (submissionType == "record") {
    auto paramBlock = submission.getApplicationParameters().blockFromValue();
    record::Record record(paramBlock);
    CertificateState certState;
    try {
      certState = m_storage->getCertificateState(record.getCertificateName(record.getName()));
      m_storage->updateCertificateState(certState);
    }
    catch (const std::exception& e) {
      certState.updateCertificateState(record);
      m_storage->addCertificateState(certState);
    }
  }
  else {
    NDN_LOG_ERROR("Submission type not recognized: " + submissionType + "\n");
    statusCode = 0;
  }
  Data reply(submission.getName());
  reply.setContent(ndn::makeNonNegativeIntegerBlock(submissionStatusType, statusCode));
  m_keyChain.sign(reply, ndn::signingByIdentity(m_config.ctPrefix));
  m_face.put(reply);
}

void
CtModule::onQuery(const Interest& query) {
  // Naming Convention: /<prefix>/REVOKE/<keyid>/<issuer>/<version>
  // need to validate query format
  NDN_LOG_TRACE("Received Query " << query);

  Name certName = query.getName();
  auto publisherId = query.getName().at(record::Record::PUBLISHER_OFFSET);
  // need more proper handling here
  certName.set(record::Record::REVOKE_OFFSET, Name::Component("KEY"));
  certName.erase(record::Record::PUBLISHER_OFFSET);

  auto state = getCertificateState(certName);
  if (state) {
    // Ct knows the answer
    NDN_LOG_TRACE("CT gets the local state\n");
    switch (state->status) {
      case CertificateStatus::REVOKED_CERTIFICATE:
        if (!state->record.getName().empty()) {
          m_face.put(state->record);
        }
        else {
          NDN_LOG_DEBUG("Certificate is marked as revoked but no corresponding record\n");
          // considered as not revoked
          m_face.put(*prepareNack(*state, publisherId, m_config.nackFreshnessPeriod));
        }
        break;
      case CertificateStatus::VALID_CERTIFICATE:
        m_face.put(*prepareNack(*state, publisherId, m_config.nackFreshnessPeriod));
        break;
      case CertificateStatus::NOTINITIALIZED:
        NDN_LOG_DEBUG("Certificate state not initialized\n");
        break;
      default:
        NDN_LOG_ERROR("Undefined status\n");
        break;
    }
  }
  else {
    // CT does not know the answer
    NDN_LOG_INFO("CT does not know the answer for " << certName << ", not respond\n");
  }
}

std::shared_ptr<nack::Nack>
CtModule::prepareNack(const CertificateState& certState, Name::Component publisherId, 
                      ndn::time::milliseconds freshnessPeriod)
{
  state::State state(certState.cert.getName(), m_keyChain);
  // currently we only have one nack code
  state.setNackCode(tlv::NackCode::NOT_REVOKED);
  state.setPublisher(publisherId);

  // need try-catch in case of not having keys
  const auto& pib = m_keyChain.getPib();
  const auto& identity = pib.getIdentity(m_config.ctPrefix);

  return state.genNack(identity.getDefaultKey().getName(), freshnessPeriod);
}

void
CtModule::onRegisterFailed(const std::string& reason)
{
  NDN_LOG_ERROR("Failed to register prefix in local hub's daemon, REASON: " << reason);
}

} // namespace ct
} // namespace ndnrevoke

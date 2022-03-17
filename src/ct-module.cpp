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
    NDN_LOG_TRACE("Record Keeper gets the local state\n");
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
    // Ct does not know the answer
    NDN_LOG_INFO("Record Keeper does not know the answer for " << certName << ", not respond\n");
  }
}

std::shared_ptr<nack::Nack>
CtModule::prepareNack(const CertificateState& certState, Name::Component publisherId, 
                      ndn::time::milliseconds freshnessPeriod)
{
  state::State state(certState.certName, m_keyChain);
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
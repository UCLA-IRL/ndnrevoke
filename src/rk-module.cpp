#include "rk-module.hpp"
#include "record-encoder.hpp"
#include "nack-encoder.hpp"
#include "state.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/util/string-helper.hpp>

namespace ndnrevoke {
namespace rk {

NDN_LOG_INIT(ndncert.rk);


// TODO: need config record Zone
RkModule::RkModule(ndn::Face& face, ndn::KeyChain& keyChain, const std::string& configPath, const std::string& storageType)
  : m_face(face)
  , m_keyChain(keyChain)
{
  // load the config and create storage
  m_config.load(configPath);
  m_storage = RkStorage::createRkStorage(storageType, m_config.rkPrefix, "");
  registerPrefix();
}

RkModule::~RkModule()
{
  for (auto& handle : m_interestFilterHandles) {
    handle.cancel();
  }
  for (auto& handle : m_registeredPrefixHandles) {
    handle.unregister();
  }
}

void
RkModule::registerPrefix()
{
  // register prefixes
  Name prefix = m_config.rkPrefix;
  // in practice, it should be a ledger, but let's denote
  // as a Record Keeper here
  prefix.append("RK");

  auto prefixId = m_face.registerPrefix(
    prefix,
    [&] (const Name& name) {
      // register for each record Zone
      // notice: this only register FIB to Face, not NFD.
      for (auto& zone : m_config.recordZones) {
         auto filterId = m_face.setInterestFilter(zone, [this] (auto&&, const auto& i) { onQuery(i); });
        m_interestFilterHandles.push_back(filterId);
      }
    },
    [this] (auto&&, const auto& reason) { onRegisterFailed(reason); });
  m_registeredPrefixHandles.push_back(prefixId);
}

std::unique_ptr<RevocationState>
RkModule::getRevocationState(const Name& certName)
{
  try {
    return std::make_unique<RevocationState>(m_storage->getRevocationState(certName));
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Cannot get revocation state record from the storage: " << e.what());
    return nullptr;
  }
}

void
RkModule::onQuery(const Interest& query) {
  // Naming Convention: /<prefix>/REVOKE/<keyid>/<issuer>/<version>
  NDN_LOG_TRACE("Received Query");

  Name certName = query.getName();
  certName.getPrefix(record::Record::PUBLISHER_OFFSET);
  certName.set(record::Record::REVOKE_OFFSET, Name::Component("KEY"));

  auto state = getRevocationState(certName);
  if (state) {
    // RK knows the answer
    NDN_LOG_TRACE("Record Keeper gets the local state\n");
    switch (state->status) {
      case RevocationStatus::REVOKED_CERTIFICATE:
        if (!state->record.getName().empty()) {
          m_face.put(state->record);
        }
        else {
          NDN_LOG_DEBUG("Certificate is marked as revoked but no corresponding record\n");
          // considered as not revoked
          m_face.put(*getNack(*state));
        }
        break;
      case RevocationStatus::VALID_CERTIFICATE:
        m_face.put(*getNack(*state));
        break;
      case RevocationStatus::NOTINITIALIZED:
        NDN_LOG_DEBUG("Revocation state not initialized\n");
        break;
      default:
        NDN_LOG_ERROR("Undefined status\n");
        break;
    }
  }
  else {
    // RK does not know the answer
    NDN_LOG_INFO("Record Keeper does not know the answer for " << certName << ", not respond\n");
  }
}

std::shared_ptr<nack::Nack>
RkModule::getNack(const RevocationState& revocationState)
{
  state::State state(revocationState.certName, m_keyChain);
  // currently we only have one nack code
  state.setNackCode(tlv::NackCode::NOT_REVOKED);

  // need try-catch in case of not having keys
  const auto& pib = m_keyChain.getPib();
  const auto& identity = pib.getIdentity(m_config.rkPrefix);
  
  // need to customize freshness period later
  return state.genNack(identity.getDefaultKey().getName(), 1_h);
}

void
RkModule::onRegisterFailed(const std::string& reason)
{
  NDN_LOG_ERROR("Failed to register prefix in local hub's daemon, REASON: " << reason);
}

} // namespace rk
} // namespace ndnrevoke

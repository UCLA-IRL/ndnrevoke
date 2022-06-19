#include "ct-module.hpp"
#include "record.hpp"
#include "nack.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/util/string-helper.hpp>

namespace ndnrevoke::ct {

NDN_LOG_INIT(ndnrevoke.ct);

CtModule::CtModule(ndn::Face& face, ndn::KeyChain& keyChain, const std::string& configPath, const std::string& storageType)
  : m_face(face)
  , m_keyChain(keyChain)
{
  // load the config and create storage
  m_config.load(configPath);
  m_storage = CtStorage::createCtStorage(storageType, m_config.ctPrefix, "");
  m_validator.load(m_config.schemaFile);
  registerPrefix();
  
  Name topic = Name(m_config.ctPrefix).append("LEDGER").append("append");
  m_ctState = std::make_unique<append::CtState>(m_config.ctPrefix, topic, m_face, m_keyChain, m_validator);
  m_ctState->listen(std::bind(&CtModule::onDataSubmission, this, _1));
}

void
CtModule::registerPrefix()
{
  // register prefixes
  Name prefix = m_config.ctPrefix;
  // let's first use "LEDGER" in protocol
  prefix.append("LEDGER");

  auto prefixId = m_face.registerPrefix(
    prefix,
    [&] (const Name& name) {
      // register for each record Zone
      // notice: this only register FIB to Face, not NFD.
      for (auto& zone : m_config.recordZones) {
        auto filterId = m_face.setInterestFilter(zone, [this] (auto&&, const auto& i) { onQuery(i); });
        NDN_LOG_TRACE("Registering filter for recordZone " << zone);
        m_handle.handleFilter(filterId);
      }
    },
    [this] (auto&&, const auto& reason) { onRegisterFailed(reason); });
  m_handle.handlePrefix(prefixId);
}

AppendStatus 
CtModule::onDataSubmission(const Data& data)
{
  NDN_LOG_TRACE("Received Submission " << data);
  AppendStatus ret;
  m_validator.validate(data,
    [this, &data, &ret] (const Data&) {
      NDN_LOG_TRACE("Submitted Data conforms to trust schema");
      try {
        m_storage->addData(data);
        ret = AppendStatus::SUCCESS;
      }
      catch (std::exception& e) {
        NDN_LOG_TRACE("Submission failed because of: " << e.what());
        ret = AppendStatus::FAILURE_STORAGE;
      }
    },
    [&ret] (const Data&, const ndn::security::ValidationError& error) {
      NDN_LOG_ERROR("Error authenticating data: " << error);
      ret = AppendStatus::FAILURE_VALIDATION_APP;
    });
  return ret;
}

void
CtModule::onQuery(const Interest& query) {
  // need to validate query format
  if (query.getForwardingHint().empty()) {
    // non-related, discard
    return;
  }

  NDN_LOG_TRACE("Received Query " << query);
  try {
    Data data = m_storage->getData(query.getName());
    NDN_LOG_TRACE("CT replies with: " << data.getName());
    m_face.put(data);
  }
  catch (std::exception& e) {
    NDN_LOG_DEBUG("CT storage cannot get the Data for reason: " << e.what());
    // reply with app layer nack
    nack::Nack nack;
    auto data = nack.prepareData(query.getName(), time::toUnixTimestamp(time::system_clock::now()));
    data->setFreshnessPeriod(m_config.nackFreshnessPeriod);
    m_keyChain.sign(*data, signingByIdentity(m_config.ctPrefix));
    NDN_LOG_TRACE("CT replies with: " << data->getName());
    m_face.put(*data);
  }
}

void
CtModule::onRegisterFailed(const std::string& reason)
{
  NDN_LOG_ERROR("Failed to register prefix in local hub's daemon, REASON: " << reason);
}

} // namespace ndnrevoke::ct

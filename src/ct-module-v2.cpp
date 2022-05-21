#include "ct-module-v2.hpp"
#include "record-encoder.hpp"
#include "nack-encoder.hpp"

#include <iostream>

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/util/string-helper.hpp>

namespace ndnrevoke {
namespace ct {

NDN_LOG_INIT(ndnrevoke.ct);

CtModuleV2::CtModuleV2(ndn::Face& face, ndn::KeyChain& keyChain, const std::string& configPath, const std::string& storageType)
  : m_face(face)
  , m_keyChain(keyChain)
{
  // load the config and create storage
  m_config.load(configPath);
  m_storage = CtStorageV2::createCtStorageV2(storageType, m_config.ctPrefix, "");
  registerPrefix();

  m_handle = std::make_shared<append::HandleCt>(m_config.ctPrefix, face, m_keyChain);

  // register prefixes
  m_handle->listenOnTopic(Name(m_config.ctPrefix).append("LEDGER").append("append"),
                          std::bind(&CtModuleV2::onDataSubmission, this, _1));
}

CtModuleV2::~CtModuleV2()
{
  for (auto& handle : m_interestFilterHandles) {
    handle.cancel();
  }
  for (auto& handle : m_registeredPrefixHandles) {
    handle.unregister();
  }
}

void
CtModuleV2::registerPrefix()
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
        m_interestFilterHandles.push_back(filterId);
      }
    },
    [this] (auto&&, const auto& reason) { onRegisterFailed(reason); });
  m_registeredPrefixHandles.push_back(prefixId);
}

tlv::AppendStatus 
CtModuleV2::onDataSubmission(const Data& data)
{
  NDN_LOG_TRACE("Received Submission " << data);
  Name name = data.getName();

  // TODO: validate with trust schema
  if (Certificate::isValidName(name)) {
    // TODO: do sth
    try {
      m_storage->addData(data);
      return tlv::AppendStatus::SUCCESS;
    }
    catch (std::exception& e) {
      NDN_LOG_TRACE("Submission failed because of: " << e.what());
      return tlv::AppendStatus::FAILURE_STORAGE;
    }
  }
  else if (Certificate::isValidName(record::Record::getCertificateName(name))) {
    // TODO: do sth
    try {
      m_storage->addData(data);
      return tlv::AppendStatus::SUCCESS;
    }
    catch (std::exception& e) {
      NDN_LOG_TRACE("Submission failed because of: " << e.what());
      return tlv::AppendStatus::FAILURE_STORAGE;
    }
  }
  return tlv::AppendStatus::FAILURE_VALIDATION;
}

void
CtModuleV2::onQuery(const Interest& query) {
  // need to validate query format
  NDN_LOG_TRACE("Received Query " << query);
  try {
    Data data = m_storage->getData(query.getName());
    NDN_LOG_DEBUG("CT replies with: " << data.getName());
    m_face.put(data);
  }
  catch (std::exception& e) {
    NDN_LOG_DEBUG("CT storage cannot get the Data for reason: " << e.what());
    // reply with app layer nack
    m_face.put(*prepareNack(query.getName(), m_config.nackFreshnessPeriod));
  }
}

std::shared_ptr<nack::Nack>
CtModuleV2::prepareNack(const Name dataName, ndn::time::milliseconds freshnessPeriod)
{
  std::shared_ptr<nack::Nack> nack = std::make_shared<nack::Nack>();
  auto nackName = dataName;
  nackName.append("nack").appendTimestamp();  
  nack->setName(nackName);
  nack->setFreshnessPeriod(freshnessPeriod);
  m_keyChain.sign(*nack, signingByIdentity(m_config.ctPrefix));
  return nack;
}

void
CtModuleV2::onRegisterFailed(const std::string& reason)
{
  NDN_LOG_ERROR("Failed to register prefix in local hub's daemon, REASON: " << reason);
}

} // namespace ct
} // namespace ndnrevoke

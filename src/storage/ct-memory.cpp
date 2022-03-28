#include "ct-memory.hpp"

namespace ndnrevoke {
namespace ct {

NDN_LOG_INIT(ndnrevoke.ct);

const std::string CtMemory::STORAGE_TYPE = "ct-storage-memory";
NDNREVOKE_REGISTER_CT_STORAGE(CtMemory);

CtMemory::CtMemory(const Name& ctName, const std::string& path)
  : CtStorage()
{
}

CertificateState
CtMemory::getCertificateState(const Name& certName)
{
  auto search = m_certStates.find(certName.toUri());
  if (search == m_certStates.end()) {
    NDN_THROW(std::runtime_error("Certificate State for " + certName.toUri() +
                                 " does not exists"));
  }
  return search->second;
}

void
CtMemory::addCertificateState(const CertificateState& state)
{
  NDN_LOG_TRACE("Adding CertificateState:\n" << state);
  auto search = m_certStates.find(state.cert.getName().toUri());
  if (search == m_certStates.end()) {
    m_certStates.insert(std::make_pair(state.cert.getName().toUri(), state));
  }
  else {
    NDN_THROW(std::runtime_error("Certificate State " + state.cert.getName().toUri() +
                                 " already exists"));
  }
}

void
CtMemory::updateCertificateState(const CertificateState& state)
{
  auto search = m_certStates.find(state.cert.getName().toUri());
  if (search == m_certStates.end()) {
    m_certStates.insert(std::make_pair(state.cert.getName().toUri(), state));
  }
  else {
    search->second = state;
  }
  NDN_LOG_TRACE("Updating CertificateState:\n" << state);
}

void
CtMemory::deleteCertificateState(const Name& certName)
{
  auto search = m_certStates.find(certName.toUri());
  if (search != m_certStates.end()) {
    m_certStates.erase(search);
  }
}

std::list<CertificateState>
CtMemory::listAllCertificateStates()
{
  std::list<CertificateState> result;
  for (const auto& entry : m_certStates) {
    result.push_back(entry.second);
  }
  return result;
}

std::list<CertificateState>
CtMemory::listAllCertificateStates(const Name& ctName)
{
  std::list<CertificateState> result;
  for (const auto& entry : m_certStates) {
    if (entry.second.ctPrefix == ctName) {
      result.push_back(entry.second);
    }
  }
  return result;
}

} // namespace ct
} // namespace ndnrevoke

#include "rk-memory.hpp"

namespace ndnrevoke {
namespace rk {

NDN_LOG_INIT(ndnrevoke.rk);

const std::string RkMemory::STORAGE_TYPE = "rk-storage-memory";
NDNREVOKE_REGISTER_RK_STORAGE(RkMemory);

RkMemory::RkMemory(const Name& rkName, const std::string& path)
  : RkStorage()
{
}

RevocationState
RkMemory::getRevocationState(const Name& certName)
{
  auto search = m_revocationStates.find(certName.toUri());
  if (search == m_revocationStates.end()) {
    NDN_THROW(std::runtime_error("Revocation State for " + certName.toUri() +
                                 " does not exists"));
  }
  return search->second;
}

void
RkMemory::addRevocationState(const RevocationState& state)
{
  NDN_LOG_TRACE("Adding RevocationState:\n" << state);
  auto search = m_revocationStates.find(state.certName.toUri());
  if (search == m_revocationStates.end()) {
    m_revocationStates.insert(std::make_pair(state.certName.toUri(), state));
  }
  else {
    NDN_THROW(std::runtime_error("Revoation State " + state.certName.toUri() +
                                 " already exists"));
  }
}

void
RkMemory::updateRevocationState(const RevocationState& state)
{
  auto search = m_revocationStates.find(state.certName.toUri());
  if (search == m_revocationStates.end()) {
    m_revocationStates.insert(std::make_pair(state.certName.toUri(), state));
  }
  else {
    search->second = state;
  }
}

void
RkMemory::deleteRevocationState(const Name& certName)
{
  auto search = m_revocationStates.find(certName.toUri());
  if (search != m_revocationStates.end()) {
    m_revocationStates.erase(search);
  }
}

std::list<RevocationState>
RkMemory::listAllRevocationStates()
{
  std::list<RevocationState> result;
  for (const auto& entry : m_revocationStates) {
    result.push_back(entry.second);
  }
  return result;
}

std::list<RevocationState>
RkMemory::listAllRevocationStates(const Name& rkName)
{
  std::list<RevocationState> result;
  for (const auto& entry : m_revocationStates) {
    if (entry.second.rkPrefix == rkName) {
      result.push_back(entry.second);
    }
  }
  return result;
}

} // namespace rk
} // namespace ndnrevoke

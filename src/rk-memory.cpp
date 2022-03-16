#include "rk-memory.hpp"

namespace ndnrevoke {
namespace rk {

const std::string RkMemory::STORAGE_TYPE = "rk-storage-memory";
NDNREVOKE_REGISTER_RK_STORAGE(RkMemory);

RkMemory::RkMemory(const Name& rkName, const std::string& path)
  : RkStorage()
{
}

RevocationState
RkMemory::getRevocationState(const StateId& stateId)
{
  auto search = m_revocationStates.find(stateId);
  if (search == m_revocationStates.end()) {
    NDN_THROW(std::runtime_error("Revocation State " + ndn::toHex(stateId.data(), stateId.size()) +
                                 " does not exists"));
  }
  return search->second;
}

void
RkMemory::addRevocationState(const RevocationState& state)
{
  auto search = m_revocationStates.find(state.stateId);
  if (search == m_revocationStates.end()) {
    m_revocationStates.insert(std::make_pair(state.stateId, state));
  }
  else {
    NDN_THROW(std::runtime_error("Revoation State " + ndn::toHex(state.stateId.data(), state.stateId.size()) +
                                 " already exists"));
  }
}

void
RkMemory::updateRevocationState(const RevocationState& state)
{
  auto search = m_revocationStates.find(state.stateId);
  if (search == m_revocationStates.end()) {
    m_revocationStates.insert(std::make_pair(state.stateId, state));
  }
  else {
    search->second = state;
  }
}

void
RkMemory::deleteRevocationState(const StateId& stateId)
{
  auto search = m_revocationStates.find(stateId);
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

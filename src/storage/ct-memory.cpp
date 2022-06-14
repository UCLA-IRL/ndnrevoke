#include "ct-memory.hpp"

namespace ndnrevoke {
namespace ct {

const std::string CtMemory::STORAGE_TYPE = "ct-storage-memory";
NDNREVOKE_REGISTER_CT_STORAGE(CtMemory);

CtMemory::CtMemory(const Name& ctName, const std::string& path)
  : CtStorage()
{
}

void
CtMemory::addData(const Data& data)
{
  Name name = data.getName();
  auto search = m_list.find(name);
  if (search != m_list.end()) {
    NDN_THROW(std::runtime_error("Data for " + name.toUri() + " already exists"));
  }
  m_list.insert(std::make_pair(name, data));
}

Data
CtMemory::getData(const Name& name)
{
  auto search = m_list.find(name);
  if (search == m_list.end()) {
    NDN_THROW(std::runtime_error("Data for " + name.toUri() + " does not exists"));
  }
  return search->second;
}

void
CtMemory::deleteData(const Name& name)
{
  auto search = m_list.find(name);
  if (search == m_list.end()) {
    NDN_THROW(std::runtime_error("Data for " + name.toUri() + " does not exists"));
  }
  m_list.erase(search);
}

} // namespace ct
} // namespace ndnrevoke

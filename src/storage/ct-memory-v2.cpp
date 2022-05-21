#include "ct-memory-v2.hpp"

namespace ndnrevoke {
namespace ct {

NDN_LOG_INIT(ndnrevoke.ct);

const std::string CtMemoryV2::STORAGE_TYPE = "ct-storage-memory-v2";
NDNREVOKE_REGISTER_CT_STORAGE_V2(CtMemoryV2);

CtMemoryV2::CtMemoryV2(const Name& ctName, const std::string& path)
  : CtStorageV2()
{
}

void
CtMemoryV2::addData(const Data& data)
{
  Name name = data.getName();
  auto search = m_list.find(name);
  if (search != m_list.end()) {
    NDN_THROW(std::runtime_error("Data for " + name.toUri() + " already exists"));
  }
  m_list.insert(std::make_pair(name, data));
}

Data
CtMemoryV2::getData(const Name& name)
{
  auto search = m_list.find(name);
  if (search == m_list.end()) {
    NDN_THROW(std::runtime_error("Data for " + name.toUri() + " does not exists"));
  }
  return search->second;
}

void
CtMemoryV2::deleteData(const Name& name)
{
  auto search = m_list.find(name);
  if (search == m_list.end()) {
    NDN_THROW(std::runtime_error("Data for " + name.toUri() + " does not exists"));
  }
  m_list.erase(search);
}

} // namespace ct
} // namespace ndnrevoke

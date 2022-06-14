#ifndef NDNREVOKE_CT_MEMORY_HPP
#define NDNREVOKE_CT_MEMORY_HPP

#include "ct-storage.hpp"

namespace ndnrevoke {
namespace ct {

class CtMemory : public CtStorage
{
public:
  CtMemory(const Name& ctName = Name(), const std::string& path = "");
  const static std::string STORAGE_TYPE;

public:
  void
  addData(const Data& data) override;

  Data
  getData(const Name& name) override;

  void
  deleteData(const Name& name) override;

private:
  std::map<Name, Data> m_list;
};

} // namespace ct
} // namespace ndnrevoke

#endif // NDNREVOKE_CT_MEMORY_HPP

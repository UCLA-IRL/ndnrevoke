#ifndef NDNREVOKE_CT_STORAGE_HPP
#define NDNREVOKE_CT_STORAGE_HPP

#include "revocation-common.hpp"

namespace ndnrevoke {
namespace ct {

class CtStorage : boost::noncopyable
{
public: 

  virtual void
  addData(const Data& data) = 0;

  virtual Data
  getData(const Name& name) = 0;

  virtual void
  deleteData(const Name& name) = 0;


public: // factory
  template<class CtStorageType>
  static void
  registerCtStorage(const std::string& ctStorageType = CtStorageType::STORAGE_TYPE)
  {
    CtStorageFactory& factory = getFactory();
    factory[ctStorageType] = [] (const Name& ctName, const std::string& path) {
      return std::make_unique<CtStorageType>(ctName, path);
    };
  }

  static std::unique_ptr<CtStorage>
  createCtStorage(const std::string& ctStorageType, const Name& ctName, const std::string& path);

  virtual
  ~CtStorage() = default;

private:
  using CtStorageCreateFunc = std::function<std::unique_ptr<CtStorage> (const Name&, const std::string&)>;
  using CtStorageFactory = std::map<std::string, CtStorageCreateFunc>;

  static CtStorageFactory&
  getFactory();
};

#define NDNREVOKE_REGISTER_CT_STORAGE(C)                         \
static class NdnRevoke ## C ## CtStorageRegistrationClass        \
{                                                                \
public:                                                          \
  NdnRevoke ## C ## CtStorageRegistrationClass()                 \
  {                                                              \
    ::ndnrevoke::ct::CtStorage::registerCtStorage<C>();          \
  }                                                              \
} g_NdnRevoke ## C ## CtStorageRegistrationVariable

} // namespace ct
} // namespace ndnrevoke

#endif // NDNREVOKE_Ct_STORAGE_HPP

#ifndef NDNREVOKE_CT_STORAGE_V2_HPP
#define NDNREVOKE_CT_STORAGE_V2_HPP

#include "revocation-common.hpp"

namespace ndnrevoke {
namespace ct {

class CtStorageV2 : boost::noncopyable
{
public: 

  virtual void
  addData(const Data& data) = 0;

  virtual Data
  getData(const Name& name) = 0;

  virtual void
  deleteData(const Name& name) = 0;


public: // factory
  template<class CtStorageTypeV2>
  static void
  registerCtStorageV2(const std::string& ctStorageType = CtStorageTypeV2::STORAGE_TYPE)
  {
    CtStorageFactoryV2& factory = getFactory();
    factory[ctStorageType] = [] (const Name& ctName, const std::string& path) {
      return std::make_unique<CtStorageTypeV2>(ctName, path);
    };
  }

  static std::unique_ptr<CtStorageV2>
  createCtStorageV2(const std::string& ctStorageType, const Name& ctName, const std::string& path);

  virtual
  ~CtStorageV2() = default;

private:
  using CtStorageCreateFuncV2 = std::function<std::unique_ptr<CtStorageV2> (const Name&, const std::string&)>;
  using CtStorageFactoryV2 = std::map<std::string, CtStorageCreateFuncV2>;

  static CtStorageFactoryV2&
  getFactory();
};

#define NDNREVOKE_REGISTER_CT_STORAGE_V2(C)                         \
static class NdnRevoke ## C ## CtStorageV2RegistrationClass        \
{                                                                \
public:                                                          \
  NdnRevoke ## C ## CtStorageV2RegistrationClass()                 \
  {                                                              \
    ::ndnrevoke::ct::CtStorageV2::registerCtStorageV2<C>();          \
  }                                                              \
} g_NdnRevoke ## C ## CtStorageV2RegistrationVariable

} // namespace ct
} // namespace ndnrevoke

#endif // NDNREVOKE_Ct_STORAGE_V2_HPP

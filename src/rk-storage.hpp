#ifndef NDNREVOKE_RK_STORAGE_HPP
#define NDNREVOKE_RK_STORAGE_HPP

#include "rk-revocation-state.hpp"

namespace ndnrevoke {
namespace rk {

class RkStorage : boost::noncopyable
{
public: // state related
  /**
   * @throw if RevocationState cannot be fetched from underlying data storage
   */
  virtual RevocationState
  getRevocationState(const Name& certName) = 0;

  /**
   * @throw if there is an existing RevocationState with the same State ID
   */
  virtual void
  addRevocationState(const RevocationState& state) = 0;

  virtual void
  updateRevocationState(const RevocationState& state) = 0;

  virtual void
  deleteRevocationState(const Name& certName) = 0;

  virtual std::list<RevocationState>
  listAllRevocationStates() = 0;

  virtual std::list<RevocationState>
  listAllRevocationStates(const Name& rkName) = 0;

public: // factory
  template<class RkStorageType>
  static void
  registerRkStorage(const std::string& rkStorageType = RkStorageType::STORAGE_TYPE)
  {
    RkStorageFactory& factory = getFactory();
    BOOST_ASSERT(factory.count(rkStorageType) == 0);
    factory[rkStorageType] = [] (const Name& rkName, const std::string& path) {
      return std::make_unique<RkStorageType>(rkName, path);
    };
  }

  static std::unique_ptr<RkStorage>
  createRkStorage(const std::string& rkStorageType, const Name& rkName, const std::string& path);

  virtual
  ~RkStorage() = default;

private:
  using RkStorageCreateFunc = std::function<std::unique_ptr<RkStorage> (const Name&, const std::string&)>;
  using RkStorageFactory = std::map<std::string, RkStorageCreateFunc>;

  static RkStorageFactory&
  getFactory();
};

#define NDNREVOKE_REGISTER_RK_STORAGE(C)                           \
static class NdnRevoke ## C ## RkStorageRegistrationClass          \
{                                                                \
public:                                                          \
  NdnRevoke ## C ## RkStorageRegistrationClass()                   \
  {                                                              \
    ::ndnrevoke::rk::RkStorage::registerRkStorage<C>();            \
  }                                                              \
} g_NdnRevoke ## C ## RkStorageRegistrationVariable

} // namespace rk
} // namespace ndnrevoke

#endif // NDNREVOKE_RK_STORAGE_HPP

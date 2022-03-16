#include "rk-storage.hpp"

namespace ndnrevoke {
namespace rk {

std::unique_ptr<RkStorage>
RkStorage::createRkStorage(const std::string& rkStorageType, const Name& rkName, const std::string& path)
{
  RkStorageFactory& factory = getFactory();
  auto i = factory.find(rkStorageType);
  return i == factory.end() ? nullptr : i->second(rkName, path);
}

RkStorage::RkStorageFactory&
RkStorage::getFactory()
{
  static RkStorage::RkStorageFactory factory;
  return factory;
}

} // namespace rk
} // namespace ndnrevoke

#include "ct-storage-v2.hpp"

namespace ndnrevoke {
namespace ct {

std::unique_ptr<CtStorageV2>
CtStorageV2::createCtStorageV2(const std::string& ctStorageType, const Name& ctName, const std::string& path)
{
  CtStorageFactoryV2& factory = getFactory();
  auto i = factory.find(ctStorageType);
  return i == factory.end() ? nullptr : i->second(ctName, path);
}

CtStorageV2::CtStorageFactoryV2&
CtStorageV2::getFactory()
{
  static CtStorageV2::CtStorageFactoryV2 factory;
  return factory;
}

} // namespace ct
} // namespace ndnrevoke

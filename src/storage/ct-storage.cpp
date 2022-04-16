#include "ct-storage.hpp"

namespace ndnrevoke {
namespace ct {

std::unique_ptr<CtStorage>
CtStorage::createCtStorage(const std::string& ctStorageType, ndn::security::KeyChain& keychain, ndn::Face &network, const Name& rkName, const std::string& path)
{
  CtStorageFactory& factory = getFactory();
  auto i = factory.find(ctStorageType);
  return i == factory.end() ? nullptr : i->second(keychain,network, rkName, path);
}

CtStorage::CtStorageFactory&
CtStorage::getFactory()
{
  static CtStorage::CtStorageFactory factory;
  return factory;
}

} // namespace ct
} // namespace ndnrevoke

#ifndef NDNREVOKE_CT_STORAGE_HPP
#define NDNREVOKE_CT_STORAGE_HPP

#include "ct-certificate-state.hpp"

namespace ndnrevoke {
namespace ct {

class CtStorage : boost::noncopyable
{
public: // state related
  /**
   * @throw if CertificateState cannot be fetched from underlying data storage
   */
  virtual CertificateState
  getCertificateState(const Name& certName) = 0;

  /**
   * @throw if there is an existing CertificateState
   */
  virtual void
  addCertificateState(const CertificateState& state) = 0;

  virtual void
  updateCertificateState(const CertificateState& state) = 0;

  virtual void
  deleteCertificateState(const Name& certName) = 0;

  virtual std::list<CertificateState>
  listAllCertificateStates() = 0;

  virtual std::list<CertificateState>
  listAllCertificateStates(const Name& ctName) = 0;

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

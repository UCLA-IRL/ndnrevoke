#ifndef NDNREVOKE_CHECKER_HPP
#define NDNREVOKE_CHECKER_HPP

#include "record.hpp"
#include "nack.hpp"
#include "error.hpp"
#include "checker-options.hpp"
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/validator-config.hpp>

namespace ndnrevoke::checker {

class Checker : boost::noncopyable
{
public:
  explicit
  Checker(ndn::Face& face, ndn::security::Validator& validator);

  void
  doIssuerCheck(const Name ledgerPrefix, const Certificate& certData,
                const onValidCallback onValid, 
                const onRevokedCallback onRevoked, 
                const onFailureCallback onFailure);

  void
  doOwnerCheck(const Name ledgerPrefix, const Certificate& certData,
               const onValidCallback onValid, 
               const onRevokedCallback onRevoked, 
               const onFailureCallback onFailure);

  void
  doCheck(const Name ledgerPrefix, const Certificate& certData, const Name::Component& revoker,
          const onValidCallback onValid, 
          const onRevokedCallback onRevoked, 
          const onFailureCallback onFailure);

private:
  void
  dispatchInterest(const std::shared_ptr<CheckerOptions>& checkerOptions,
                   const Name::Component& revoker);
  void
  onValidationSuccess(const std::shared_ptr<CheckerOptions>& checkerOptions, const Data& data);

  void
  onValidationFailure(const std::shared_ptr<CheckerOptions>& checkerOptions, const ndn::security::ValidationError& error);
  ndn::Face& m_face;
  ndn::security::Validator& m_validator;
};

} // namespace ndnrevoke::checker

#endif // NDNREVOKE_CHECKER_HPP

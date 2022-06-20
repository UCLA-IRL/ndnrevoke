#include "checker.hpp"
#include "record.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
namespace ndnrevoke::checker {

NDN_LOG_INIT(ndnrevoke.checker);

Checker::Checker(ndn::Face& face, ndn::security::Validator& validator)
  : m_face(face)
  , m_validator(validator)
{
}

void
Checker::doIssuerCheck(const Name ledgerPrefix, const Certificate& certData,
                       const onValidCallback onValid, 
                       const onRevokedCallback onRevoked, 
                       const onFailureCallback onFailure)
{
  doCheck(ledgerPrefix, certData, certData.getIssuerId(),
          onValid, onRevoked, onFailure);
}

void
Checker::doOwnerCheck(const Name ledgerPrefix, const Certificate& certData,
                      const onValidCallback onValid, 
                      const onRevokedCallback onRevoked, 
                      const onFailureCallback onFailure)
{
  doCheck(ledgerPrefix, certData, Name::Component("self"),
          onValid, onRevoked, onFailure);
}

void
Checker::doCheck(const Name ledgerPrefix, const Certificate& certData, const Name::Component& revoker,
                 const onValidCallback onValid, 
                 const onRevokedCallback onRevoked, 
                 const onFailureCallback onFailure)
{
  auto state = std::make_shared<CheckerOptions>(m_face, certData, onValid, onRevoked, onFailure);
  dispatchInterest(state, ledgerPrefix, revoker);
}

void
Checker::dispatchInterest(const std::shared_ptr<CheckerOptions>& checkerOptions,
                          const Name& ledgerPrefix, const Name::Component& revoker)
{
  if (checkerOptions->exhaustRetries()) {
    return checkerOptions->onFailure(Error(Error::Code::TIMEOUT, "Running out of retries"));
  }

  m_face.expressInterest(*checkerOptions->makeInterest(ledgerPrefix, revoker),
    [this, checkerOptions] (auto&&, auto& data) {
      // naming conventiion check
      m_validator.validate(data,
        [this, checkerOptions, data] (const Data&) {
          NDN_LOG_DEBUG("Data conforms to trust schema");
          return onValidationSuccess(checkerOptions, data);
        },
        [this, checkerOptions, data] (const Data&, const ndn::security::ValidationError& error) {
          NDN_LOG_ERROR("Error authenticating data: " << error);
          return onValidationFailure(checkerOptions, error);
        }
      );
    },
    [checkerOptions] (auto& i, auto&&) {
      return checkerOptions->onFailure(Error(Error::Code::NACK, i.getName().toUri()));
    },
    [this, checkerOptions, ledgerPrefix, revoker] (const auto&) {
       return dispatchInterest(checkerOptions, ledgerPrefix, revoker);
    }
  );
}

void
Checker::onValidationSuccess(const std::shared_ptr<CheckerOptions>& checkerOptions, const Data& data)
{
  Name dataName = data.getName();
  if (record::Record::isValidName(dataName)) {
    return checkerOptions->onRevoked(record::Record(data));
  }
  if (nack::RecordNack::isValidName(dataName)) {
    return checkerOptions->onValid(nack::RecordNack(data));
  }
  else {
    return checkerOptions->onFailure(Error(Error::Code::PROTO_SPECIFIC, "Uncognized data format")); 
  }
}

void
Checker::onValidationFailure(const std::shared_ptr<CheckerOptions>& checkerOptions, const ndn::security::ValidationError& error)
{
  return checkerOptions->onFailure(Error(Error::Code::VALIDATION_ERROR, error.getInfo()));
}
} // namespace ndnrevoke

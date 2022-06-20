#ifndef NDNREVOKE_CHECKER_STATE_HPP
#define NDNREVOKE_CHECKER_STATE_HPP

#include "record.hpp"
#include "nack.hpp"
#include "error.hpp"
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/validator-config.hpp>

namespace ndnrevoke::checker {

using onValidCallback = std::function<void(const Certificate&, const nack::RecordNack&)>;
using onRevokedCallback = std::function<void(const Certificate&, const record::Record&)>;
using onFailureCallback = std::function<void(const Certificate&, const Error&)>;

class CheckerOptions : boost::noncopyable
{
public:
  const ssize_t CHECKER_MAX_RETRIES = 3;

  explicit
  CheckerOptions(ndn::Face& face,
                 const Certificate& certData,
                 const onValidCallback onValid, 
                 const onRevokedCallback onRevoked, 
                 const onFailureCallback onFailure);
  
  std::shared_ptr<Interest>
  makeInterest(const Name& ledgerPrefix, const Name::Component& revoker);

  bool
  exhaustRetries()
  {
    return m_retryCount++ > CHECKER_MAX_RETRIES? true : false;
  }

  void
  onValid(const nack::RecordNack& nack)
  {
    return m_vCb(m_cert, nack);
  }

  void
  onRevoked(const record::Record& record)
  {
    return m_rCb(m_cert, record);
  }

  void
  onFailure(const Error& error)
  {
    return m_fCb(m_cert, error);
  }

private:

  void
  onData(const Interest&, const Data& data);

  void
  onValidationSuccess(const Data& data);

  void
  onValidationFailure(const Data& data, const ndn::security::ValidationError& error);

  void
  onNack(const Interest&, const ndn::lp::Nack& nack);

  void
  onTimeout(const Interest& interest);

  ndn::Face& m_face;

  Certificate m_cert;
  onValidCallback m_vCb;
  onRevokedCallback m_rCb;
  onFailureCallback m_fCb;
  ssize_t m_retryCount = 0;
};

} // namespace ndnrevoke::checker

#endif // NDNREVOKE_CHECKER_STATE_HPP

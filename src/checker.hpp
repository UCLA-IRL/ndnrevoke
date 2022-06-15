#ifndef NDNREVOKE_CHECKER_HPP
#define NDNREVOKE_CHECKER_HPP

#include "record.hpp"
#include "nack.hpp"
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/face.hpp>

namespace ndnrevoke {
namespace checker {

using onValidCallback = std::function<void(const nack::Nack&)>;
using onRevokedCallback = std::function<void(const record::Record&)>;
// cuz timeout or nack, or unknown type data, return the following reason
using onFailureCallback = std::function<void(const std::string)>;

class Checker : boost::noncopyable
{
public:
  struct CheckerCbs
  {
    onValidCallback vCb;
    onRevokedCallback rCb;
    onFailureCallback fCb;
    int remainingRetry = 3;
  };
  explicit
  Checker(ndn::Face& face);

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
  doCheck(const Name ledgerPrefix, const Certificate& certData, const Name::Component& publisher,
          const onValidCallback onValid, 
          const onRevokedCallback onRevoked, 
          const onFailureCallback onFailure);

private:
  void
  onData(const Interest&, const Data& data);

  void
  onNack(const Interest&, const ndn::lp::Nack& nack);

  void
  onTimeout(const Interest& interest);

  ndn::Face& m_face;
  std::unordered_map<Name, CheckerCbs> m_states;
};

} // namespace checker
} // namespace ndnrevoke

#endif // NDNREVOKE_CHECKER_HPP

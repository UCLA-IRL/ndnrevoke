#ifndef NDNREVOKE_REVOKER_HPP
#define NDNREVOKE_REVOKER_HPP

#include <optional>
#include "revocation-common.hpp"
#include "record.hpp"
#include "nack.hpp"
#include <ndn-cxx/security/key-chain.hpp>

namespace ndnrevoke::revoker {

class Revoker : boost::noncopyable
{
public:
  explicit
  Revoker(ndn::KeyChain& keyChain);

  std::shared_ptr<Data>
  revokeAsIssuer(const Certificate& certData, const tlv::ReasonCode reason);

  std::shared_ptr<Data>
  revokeAsIssuer(const Certificate& certData, const tlv::ReasonCode reason,
                 const time::milliseconds notBefore,
                 const time::milliseconds freshnessPeriod = 100_h);

  std::shared_ptr<Data>
  revokeAsOwner(const Certificate& certData, const tlv::ReasonCode reason);

  std::shared_ptr<Data>
  revokeAsOwner(const Certificate& certData, const tlv::ReasonCode reason,
                const time::milliseconds notBefore,
                const time::milliseconds freshnessPeriod = 100_h);

  std::shared_ptr<Data>
  revokeAs(const Certificate& certData, const tlv::ReasonCode reason,
           const Name::Component revokerId);

  std::shared_ptr<Data>
  revokeAs(const Certificate& certData, const tlv::ReasonCode reason,
           const time::milliseconds notBefore,
           const Name::Component revokerId,
           const time::milliseconds freshnessPeriod);

  static const time::milliseconds recordFreshness;
private:
  std::shared_ptr<Data>
  sign(std::shared_ptr<Data> data, const Certificate& cert, const Name::Component revokerId);

  ndn::KeyChain& m_keyChain;
};

} // namespace ndnrevoke::revoker

#endif // NDNREVOKE_REVOKER_HPP

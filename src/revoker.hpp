#ifndef NDNREVOKE_REVOKER_HPP
#define NDNREVOKE_REVOKER_HPP

#include <optional>
#include "revocation-common.hpp"
#include "record.hpp"
#include "record-encoder.hpp"
#include "nack.hpp"
#include <ndn-cxx/security/key-chain.hpp>

namespace ndnrevoke {
namespace revoker {

class Revoker : boost::noncopyable
{
public:
  explicit
  Revoker(ndn::KeyChain& keyChain);
  
  std::shared_ptr<record::Record>
  revokeAsIssuer(const Certificate& certData, tlv::ReasonCode reason, uint64_t notBefore,
                 const ndn::time::milliseconds freshnessPeriod = 100_h);

  std::shared_ptr<record::Record>
  revokeAsOwner(const Certificate& certData, tlv::ReasonCode reason, uint64_t notBefore,
                const ndn::time::milliseconds freshnessPeriod = 100_h);

  std::shared_ptr<record::Record>
  revokeAs(const Certificate& certData, tlv::ReasonCode reason, uint64_t notBefore,
           Name::Component id,
           const ndn::time::milliseconds freshnessPeriod);
private:
  ndn::KeyChain& m_keyChain;
};

} // namespace revoker
} // namespace ndnrevoke

#endif // NDNREVOKE_REVOKER_HPP

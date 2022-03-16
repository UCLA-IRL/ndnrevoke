#ifndef NDNREVOKE_NACK_HPP
#define NDNREVOKE_NACK_HPP

#include "revocation-common.hpp"

#include <ndn-cxx/security/key-chain.hpp>

namespace ndnrevoke {
namespace nack {

class Nack : public Data
{
public:
  Nack();
  
  explicit
  Nack(Data&& data);

  explicit
  Nack(const Block& block);

  explicit
  Nack(const Data& data);

  // /<prefix>/REVOKE/<keyid>/<issuer>/<version>/<publisher>/nack/<timestamp>
  static const ssize_t TIMESTAMP_OFFSET;
  static const ssize_t NACK_OFFSET;
  static const ssize_t PUBLISHER_OFFSET;
  static const ssize_t REVOKE_OFFSET;
};

} // namespace nack
} // namespace ndncert

#endif // NDNREVOKE_NACK_HPP

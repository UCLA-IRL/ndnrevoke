#ifndef NDNREVOKE_RECORD_HPP
#define NDNREVOKE_RECORD_HPP

#include "revocation-common.hpp"

#include <ndn-cxx/security/key-chain.hpp>

namespace ndnrevoke {
namespace record {

class Record : public Data
{
public:
  Record();
  
  explicit
  Record(Data&& data);

  explicit
  Record(const Block& block);

  explicit
  Record(const Data& data);
  
  // /<prefix>/REVOKE/<keyid>/<issuer>/<version>/<publisher>
  static const ssize_t PUBLISHER_OFFSET;
  static const ssize_t REVOKE_OFFSET;
};

} // namespace record
} // namespace ndncert

#endif // NDNREVOKE_RECORD_HPP

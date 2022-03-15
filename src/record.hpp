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
};

} // namespace record
} // namespace ndncert

#endif // NDNREVOKE_REVOCATION_RECORD_HPP

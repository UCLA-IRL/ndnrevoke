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

  // Name&
  // toCertName()
  // {
  //   auto certName = std::make_unique<Name>(getName());
  //   certName->getPrefix(PUBLISHER_OFFSET);
  //   certName->set(REVOKE_OFFSET, Name::Component("KEY"));
  //   return *certName;
  // }
  
  // /<prefix>/REVOKE/<keyid>/<issuer>/<version>/<publisher>
  static const ssize_t PUBLISHER_OFFSET;
  static const ssize_t REVOKE_OFFSET;
  static const ssize_t KEY_OFFSET;

  static Name getRevocationRecordPrefix(Name certName);
  static Name getCertificateName(const Name recordName);
};

std::ostream&
operator<<(std::ostream& os, const Record& record);
} // namespace record
} // namespace ndnrevoke

#endif // NDNREVOKE_RECORD_HPP

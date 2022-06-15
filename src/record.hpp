#ifndef NDNREVOKE_RECORD_HPP
#define NDNREVOKE_RECORD_HPP

#include "revocation-common.hpp"

namespace ndnrevoke::record {

class Record : boost::noncopyable
{
public:
  class Error : public ndn::tlv::Error
  {
  public:
    using ndn::tlv::Error::Error;
  };

  Record();

  explicit
  Record(const Data& data);

  explicit
  Record(const Block& block);

  void
  fromData(const Data& data);
  
  std::shared_ptr<Data>
  prepareData();

  const Name
  getName() const
  {
    return m_name;
  }

  const ndn::span<const uint8_t>
  getPublicKeyHash() const
  {
    return m_publicKeyHash;
  }

  tlv::ReasonCode
  getReason() const
  {
    return m_reason;
  }

  const time::milliseconds
  getTimestamp() const
  {
    return m_timestamp;
  }

  const optional<time::milliseconds>
  getNotBefore() const
  {
    return m_notBefore;
  }

  bool
  hasNotBefore() const
  {
    return m_notBefore.has_value();
  }
  
  Record&
  setName(const Name& name);

  Record&
  setPublicKeyHash(const ndn::span<const uint8_t> hash);

  Record&
  setReason(const tlv::ReasonCode reason);

  Record&
  setTimestamp(const ndn::time::milliseconds timestamp);

  Record&
  setNotBefore(ndn::time::milliseconds notBefore);

  // /<prefix>/REVOKE/<keyid>/<issuer>/<version>/<revoker>
  static const ssize_t REVOKER_OFFSET;
  static const ssize_t KEYWORD_OFFSET;
  static const ssize_t KEYID_OFFSET;

  static Name getRevocationRecordPrefix(Name certName);
  static Name getCertificateName(const Name recordName);


  static bool isValidName(const Name name);

private:
  Name m_name;
  ndn::span<const uint8_t> m_publicKeyHash;
  tlv::ReasonCode m_reason;
  ndn::time::milliseconds m_timestamp;
  optional<ndn::time::milliseconds> m_notBefore;
};

std::ostream&
operator<<(std::ostream& os, const Record& record);
} // namespace ndnrevoke::record

#endif // NDNREVOKE_RECORD_HPP

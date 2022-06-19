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

  const span<const uint8_t>
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
  setPublicKeyHash(const span<const uint8_t> hash);

  Record&
  setReason(const tlv::ReasonCode reason);

  Record&
  setTimestamp(const time::milliseconds timestamp);

  Record&
  setNotBefore(const time::milliseconds notBefore);

  static bool isValidName(const Name name);

  // /<prefix>/REVOKE/<keyid>/<issuer>/<version>/<revoker>
  static const ssize_t REVOKER_OFFSET;
  static const ssize_t KEYWORD_OFFSET;
  static const ssize_t KEYID_OFFSET;

private:
  Name m_name;
  span<const uint8_t> m_publicKeyHash;
  tlv::ReasonCode m_reason;
  ndn::time::milliseconds m_timestamp;
  optional<time::milliseconds> m_notBefore;
};

std::string reasonToString(tlv::ReasonCode reason);

std::ostream&
operator<<(std::ostream& os, const Record& record);
} // namespace ndnrevoke::record

#endif // NDNREVOKE_RECORD_HPP

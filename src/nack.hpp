#ifndef NDNREVOKE_NACK_HPP
#define NDNREVOKE_NACK_HPP

#include "revocation-common.hpp"

namespace ndnrevoke::nack {

class Nack : boost::noncopyable
{
public:
  class Error : public ndn::tlv::Error
  {
  public:
    using ndn::tlv::Error::Error;
  };

  Nack();

  explicit
  Nack(const Block& block);

  explicit
  Nack(const Data& data);

  void
  fromData(const Data& data);

  const Name
  getName() const
  {
    return m_name;
  }

  const Name
  getRecordName() const
  {
    return Name(m_name.getPrefix(NACK_OFFSET));
  }

  const Name
  getCertName() const
  {
    return Name(m_name.getPrefix(PUBLISHER_OFFSET));
  }

  const ndn::time::milliseconds
  getTimestamp() const
  {
    auto timestamp = m_name.get(TIMESTAMP_OFFSET).toTimestamp();
    return ndn::time::toUnixTimestamp(timestamp);   
  }

  // /<prefix>/REVOKE/<keyid>/<issuer>/<version>/<publisher>/nack/<timestamp>
  static const ssize_t TIMESTAMP_OFFSET;
  static const ssize_t NACK_OFFSET;
  static const ssize_t PUBLISHER_OFFSET;
  static const ssize_t REVOKE_OFFSET;

  static Name
  getCertificateName(const Name nackName);

  std::shared_ptr<Data>
  prepareData(const Name recordName, const ndn::time::milliseconds timestamp);

private:
  Name m_name;
};

} // namespace ndnrevoke::nack

#endif // NDNREVOKE_NACK_HPP

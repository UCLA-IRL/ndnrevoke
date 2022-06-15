#ifndef NDNREVOKE_NACK_HPP
#define NDNREVOKE_NACK_HPP

#include "revocation-common.hpp"
#include "record.hpp"

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

  const time::milliseconds
  getTimestamp() const
  {
    auto timestamp = m_name.get(TIMESTAMP_OFFSET).toTimestamp();
    return time::toUnixTimestamp(timestamp);   
  }

  std::shared_ptr<Data>
  prepareData(const Name dataName, const time::milliseconds timestamp);

  static bool isValidName(const Name name);

  // /<data-prefix>/nack/<timestamp>
  static const ssize_t TIMESTAMP_OFFSET;
  static const ssize_t NACK_OFFSET;

protected:
  Name m_name;
};

class RecordNack : public Nack
{
public:
  explicit
  RecordNack(const Block& block);

  explicit
  RecordNack(const Data& data);

  const Name
  getRecordName() const
  {
    return Name(m_name.getPrefix(NACK_OFFSET));
  }

  const Name
  getCertName() const
  {
    return Name(m_name.getPrefix(PUBLISHER_OFFSET)
                      .set(Certificate::KEY_COMPONENT_OFFSET, Name::Component("KEY")));
  }

  static bool isValidName(const Name name);

  // /<prefix>/REVOKE/<keyid>/<issuer>/<version>/<publisher>/nack/<timestamp>
  static const ssize_t PUBLISHER_OFFSET;
  static const ssize_t REVOKE_OFFSET;
};

} // namespace ndnrevoke::nack

#endif // NDNREVOKE_NACK_HPP

#include "nack.hpp"

namespace ndnrevoke {
namespace nack {

const ssize_t Nack::TIMESTAMP_OFFSET = -1;
const ssize_t Nack::NACK_OFFSET = -2;
const ssize_t Nack::PUBLISHER_OFFSET = -3;
const ssize_t Nack::REVOKE_OFFSET = -7;

Nack::Nack()
{
}

Nack::Nack(const Block& block)
  : Nack(Data(block))
{
}

Nack::Nack(const Data& data)
{
  Nack nack;
  nack.fromData(data);
  m_name = nack.getName();
}


void
Nack::fromData(const Data& data)
{
  m_name = data.getName();
}

std::shared_ptr<Data>
Nack::prepareData(const Name recordName, time::milliseconds timestamp)
{
  Name name(recordName);
  name.appendTimestamp(ndn::time::fromUnixTimestamp(timestamp));
  auto data = std::make_shared<Data>(name);
  data->setContentType(ndn::tlv::ContentType_Nack);
  return data;
}

Name
Nack::getCertificateName(const Name nackName) {
  Name certName(nackName);
  certName.set(nack::Nack::REVOKE_OFFSET, Name::Component("KEY"));
  return certName.getPrefix(-3);;
}

} // namespace nack
} // namespace ndnrevoke
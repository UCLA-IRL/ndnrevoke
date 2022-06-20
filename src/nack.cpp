#include "nack.hpp"

namespace ndnrevoke {
namespace nack {

const ssize_t Nack::TIMESTAMP_OFFSET = -1;
const ssize_t Nack::NACK_OFFSET = -2;
const ssize_t RecordNack::PUBLISHER_OFFSET = -3;
const ssize_t RecordNack::REVOKE_OFFSET = -7;

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
Nack::prepareData(const Name dataName, time::milliseconds timestamp)
{
  Name name(dataName);
  name.append("nack");
  name.appendTimestamp(ndn::time::fromUnixTimestamp(timestamp));
  auto data = std::make_shared<Data>(name);
  data->setContentType(ndn::tlv::ContentType_Nack);
  return data;
}

bool
Nack::isValidName(const Name name)
{
  return name.get(NACK_OFFSET) == Name::Component("nack") &&
         name.get(TIMESTAMP_OFFSET).isTimestamp();
}

RecordNack::RecordNack(const Block& block)
  : Nack(Data(block))
{
}

RecordNack::RecordNack(const Data& data)
{
  Nack nack;
  nack.fromData(data);
  m_name = nack.getName();
}

bool
RecordNack::isValidName(const Name name)
{
  return record::Record::isValidName(name.getPrefix(NACK_OFFSET)) &&
         name.get(NACK_OFFSET) == Name::Component("nack") &&
         name.get(TIMESTAMP_OFFSET).isTimestamp();
}

std::ostream&
operator<<(std::ostream& os, const Nack& nack)
{
  os << "Nacked Data Name: "
     << nack.getName().getPrefix(Nack::NACK_OFFSET) << "\n"
     << "Nack Timestamp: ["
     << time::toString(time::fromUnixTimestamp(nack.getTimestamp())) << "]\n";
  return os;
}

} // namespace nack
} // namespace ndnrevoke
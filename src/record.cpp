#include "record.hpp"

namespace ndnrevoke::record {

const ssize_t Record::REVOKER_OFFSET = -1;
const ssize_t Record::KEYWORD_OFFSET = -5;
const ssize_t Record::KEYID_OFFSET = -4;

Record::Record()
{
}

Record::Record(const Block& block)
  : Record(Data(block))
{
}

Record::Record(const Data& data)
{
  Record record;
  record.fromData(data);
  m_name = record.getName();
  m_publicKeyHash = record.getPublicKeyHash();
  m_timestamp = record.getTimestamp();
  m_reason = record.getReason();
  if (record.hasNotBefore()) {
    m_notBefore = record.getNotBefore();
  }
}

Record&
Record::setName(const Name& name)
{
  m_name = name;
  return *this;
}

Record&
Record::setPublicKeyHash(const span<const uint8_t> hash)
{
  m_publicKeyHash = hash;
  return *this;
}

Record&
Record::setReason(const tlv::ReasonCode reason)
{
  m_reason = reason;
  return *this;
}

Record&
Record::setTimestamp(const time::milliseconds timestamp)
{
  m_timestamp = timestamp;
  return *this;
}

Record&
Record::setNotBefore(const time::milliseconds notBefore)
{
  m_notBefore = notBefore;
  return *this;
}

void
Record::fromData(const Data& data)
{
  if (!isValidName(data.getName())) {
    NDN_THROW(Error("Record does not conform to the naming convention"));
  }
  m_name = data.getName();
  Block content = data.getContent();

  content.parse();
  for (const auto &item : content.elements()) {
    switch (item.type()) {
      case tlv::PublicKeyHash:
        m_publicKeyHash = make_span<const uint8_t>(item.value(), item.value_size());
        break;
      case tlv::RevocationTimestamp:
        m_timestamp = time::milliseconds(readNonNegativeInteger(item));
        break;
      case tlv::NotBefore:
        m_notBefore = time::milliseconds(readNonNegativeInteger(item));
        break;
      case tlv::RevocationReason:
        m_reason = static_cast<tlv::ReasonCode>(readNonNegativeInteger(item));
        break;
      default:
        if (ndn::tlv::isCriticalType(item.type())) {
          NDN_THROW(Error("Unrecognized TLV Type: " + std::to_string(item.type())));
        }
        else {
          //ignore
        }
        break;
    }
  }
}

std::shared_ptr<Data>
Record::prepareData()
{
  auto data = std::make_shared<Data>(m_name);
  Block content(ndn::tlv::Content);
  content.push_back(ndn::makeNonNegativeIntegerBlock(tlv::RevocationTimestamp, m_timestamp.count()));
  content.push_back(ndn::makeNonNegativeIntegerBlock(tlv::RevocationReason, static_cast<uint64_t>(m_reason)));
  content.push_back(ndn::makeBinaryBlock(tlv::PublicKeyHash, m_publicKeyHash));
  if (hasNotBefore()) {
    content.push_back(ndn::makeNonNegativeIntegerBlock(tlv::NotBefore, m_notBefore.value().count()));
  }
  data->setContentType(ndn::tlv::ContentType_Key);
  data->setContent(content);
  return data; 
}

bool
Record::isValidName(const Name name)
{
  Name certName(name);
  certName.set(record::Record::KEYWORD_OFFSET, Name::Component("KEY"));
  certName.erase(record::Record::REVOKER_OFFSET);
  return name.get(REVOKER_OFFSET).isGeneric() &&
         name.get(REVOKER_OFFSET - 1).isVersion() && // Certificate::isValidName should have done this
         Certificate::isValidName(certName);
}

std::string reasonToString(tlv::ReasonCode reason)
{
  switch (reason) {
    case tlv::ReasonCode::UNSPECIFIED:
      return "UNSPECIFIED";
    case tlv::ReasonCode::KEY_COMPROMISE:
      return "KEY_COMPROMISE";
    case tlv::ReasonCode::CA_COMPROMISE:
      return "CA_COMPROMISE";
    case tlv::ReasonCode::SUPERSEDED:
      return "SUPERSEDED";
    case tlv::ReasonCode::INVALID:
      return "INVALID";
    default:
      return "Unrecognized reason";
  }
}

std::ostream&
operator<<(std::ostream& os, const Record& record)
{
  os << "Name: " << record.getName() << "\n"
     << "   Public Key Hash: [" <<  ndn::toHex(record.getPublicKeyHash()) << "]\n"
     << "   Revocation Timestamp: ["
     << time::toString(time::fromUnixTimestamp(record.getTimestamp())) << "]\n"
     << "   Revocation Reason: [" << reasonToString(record.getReason()) << "]\n";

  if (record.hasNotBefore()) {
    os << "   Revocation Not Before: ["
       << time::toString(time::fromUnixTimestamp(record.getNotBefore().value())) << "]\n";
  }
  return os;
}

} // namespace ndnrevoke::record
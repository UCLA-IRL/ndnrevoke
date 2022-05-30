#include "record.hpp"
#include "record-encoder.hpp"

namespace ndnrevoke {
namespace record {

const ssize_t Record::PUBLISHER_OFFSET = -1;
const ssize_t Record::REVOKE_OFFSET = -5;
const ssize_t Record::KEY_OFFSET = -4;

Record::Record()
{
}

Record::Record(Data&& data)
  : Data(std::move(data))
{
}
Record::Record(const Data& data)
  : Record(Data(data))
{
}

Record::Record(const Block& block)
  : Record(Data(block))
{
}

Name Record::getRevocationRecordPrefix(Name certName) {
    certName.set(REVOKE_OFFSET + 1, Name::Component("REVOKE"));
    return certName;
}

Name Record::getCertificateName(const Name recordName) {
    Name certName(recordName);
    certName.set(record::Record::REVOKE_OFFSET, Name::Component("KEY"));
    certName.erase(record::Record::PUBLISHER_OFFSET);
    return certName;
}

std::ostream&
operator<<(std::ostream& os, const Record& record)
{
  os << "Name: " << record.getName() << "\n"
     << "MetaInfo: [" << record.getMetaInfo() << "]\n";

  if (record.hasContent()) {
    os << "Content: [" << record.getContent().value_size() << " bytes]\n";
    ndn::span<const uint8_t> hash;
    uint64_t timestamp; 
    tlv::ReasonCode reason; 
    uint64_t notBefore;
    recordtlv::decodeRecordContent2(record.getContent(), hash, timestamp, reason, notBefore);    
    os << "   Public Key Hash: [" <<  ndn::toHex(hash) << "]\n"
       << "   Revocation Timestamp: [" << timestamp << "]\n"
       << "   Revocation Reason: [" << static_cast<uint64_t>(reason) << "]\n"
       << "   Revocation Not Before: [" << notBefore << "]\n";
  }

  os << "Signature: [type: " << static_cast<ndn::tlv::SignatureTypeValue>(record.getSignatureType())
     << ", length: "<< record.getSignatureValue().value_size() << "]\n"
     << "   KeyLocator: [" << record.getKeyLocator().value().getName() << "]\n";
  return os;
}

} // namespace record
} // namespace ndnrevoke
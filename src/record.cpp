#include "record.hpp"

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

Name Record::getCertificateName(Name revocationName) {
    revocationName.set(record::Record::REVOKE_OFFSET, Name::Component("KEY"));
    revocationName.erase(record::Record::PUBLISHER_OFFSET);
    return revocationName;
}

} // namespace record
} // namespace ndnrevoke
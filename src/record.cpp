#include "record.hpp"

namespace ndnrevoke {
namespace record {

const ssize_t Record::PUBLISHER_OFFSET = -1;
const ssize_t Record::REVOKE_OFFSET = -5;

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
    certName.set(REVOKE_OFFSET, Name::Component("REVOKE"));
    return certName;
}

Name Record::getCertificateName(Name revocationName) {
    revocationName.set(REVOKE_OFFSET, Name::Component("KEY"));
    revocationName.erase(record::Record::PUBLISHER_OFFSET);
    return revocationName;
}

} // namespace record
} // namespace ndnrevoke
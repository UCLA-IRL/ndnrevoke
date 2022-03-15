#include "record.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndnrevoke {
namespace record {

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

} // namespace record
} // namespace ndnrevoke
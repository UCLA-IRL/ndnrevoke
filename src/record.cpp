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

} // namespace record
} // namespace ndnrevoke
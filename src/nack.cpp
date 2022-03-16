#include "nack.hpp"

namespace ndnrevoke {
namespace nack {

const ssize_t Nack::TIMESTAMP_OFFSET = -1;
const ssize_t Nack::NACK_OFFSET = -2;
const ssize_t Nack::PUBLISHER_OFFSET = -3;
const ssize_t Nack::REVOKE_OFFSET = -7;

Nack::Nack()
{
  setContentType(ndn::tlv::ContentType_Nack);
}

Nack::Nack(Data&& data)
  : Data(std::move(data))
{
}
Nack::Nack(const Data& data)
  : Nack(Data(data))
{
}

Nack::Nack(const Block& block)
  : Nack(Data(block))
{
}

} // namespace nack
} // namespace ndnrevoke
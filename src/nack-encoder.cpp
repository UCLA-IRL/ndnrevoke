#include "nack-encoder.hpp"

namespace ndnrevoke {

Block
nacktlv::encodeNackContent(optional<tlv::NackCode> nackCode)
{
  Block content(ndn::tlv::Content);
  BOOST_ASSERT(nackCode.has_value());
  content.push_back(ndn::makeNonNegativeIntegerBlock(tlv::NackReason, static_cast<uint64_t>(nackCode.value())));
  return content;
}

void
nacktlv::decodeNackContent(const Block& nackContent, state::State& state)
{
  nackContent.parse();
  for (const auto &item : nackContent.elements()) {
    switch (item.type()) {
      case tlv::NackReason:
        state.m_nackCode = static_cast<tlv::NackCode>(readNonNegativeInteger(item));
        break;
      default:
        if (ndn::tlv::isCriticalType(item.type())) {
          NDN_THROW(std::runtime_error("Unrecognized TLV Type: " + std::to_string(item.type())));
        }
        else {
          //ignore
        }
        break;
    }
  }
}

} // namespace ndnrevoke

#include "record-encoder.hpp"

namespace ndnrevoke {

Block
recordtlv::encodeRecordContent(const std::vector<uint8_t>& publicKeyHash, const tlv::ReasonCode revocationReason)
{
  Block content(ndn::tlv::Content);
  auto revocationTimestamp = time::toUnixTimestamp(time::system_clock::now()).count();
  content.push_back(ndn::makeNonNegativeIntegerBlock(tlv::RevocationTimestamp, revocationTimestamp));
  content.push_back(ndn::makeBinaryBlock(tlv::PublicKeyHash, publicKeyHash.data(), publicKeyHash.size()));
  content.push_back(ndn::makeNonNegativeIntegerBlock(tlv::RevocationReason, static_cast<uint64_t>(revocationReason)));
  return content;
}

void
recordtlv::decodeRecordContent(const Block& recordContent, state::State& state)
{
  for (const auto &item : recordContent.elements()) {
    switch (item.type()) {
      case tlv::PublicKeyHash:
        state.m_publicKeyHash.assign(recordContent.get(tlv::PublicKeyHash).begin(), recordContent.get(tlv::PublicKeyHash).end());
        break;
      case tlv::RevocationTimestamp:
        state.m_revocationTimestamp = readNonNegativeInteger(item);
        break;
      case tlv::RevocationReason:
        state.m_revocationReason = static_cast<tlv::ReasonCode>(readNonNegativeInteger(item));
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

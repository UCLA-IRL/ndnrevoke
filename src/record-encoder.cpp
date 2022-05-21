#include "record-encoder.hpp"
#include <iostream>

namespace ndnrevoke {

Block
recordtlv::encodeRecordContent(const std::vector<uint8_t>& publicKeyHash, const tlv::ReasonCode revocationReason)
{
  Block content(ndn::tlv::Content);
  auto revocationTimestamp = time::toUnixTimestamp(time::system_clock::now()).count();
  content.push_back(ndn::makeNonNegativeIntegerBlock(tlv::RevocationTimestamp, revocationTimestamp));
  content.push_back(ndn::makeBinaryBlock(tlv::PublicKeyHash, publicKeyHash));
  return content;
}

Block
recordtlv::encodeRecordContent2(ndn::span<const uint8_t> publicKeyHash, const tlv::ReasonCode revocationReason, uint64_t notBefore)
{
  Block content(ndn::tlv::Content);
  auto revocationTimestamp = time::toUnixTimestamp(time::system_clock::now()).count();
  content.push_back(ndn::makeNonNegativeIntegerBlock(tlv::RevocationTimestamp, revocationTimestamp));
  content.push_back(ndn::makeNonNegativeIntegerBlock(tlv::NotBefore, notBefore));
  content.push_back(ndn::makeNonNegativeIntegerBlock(tlv::RevocationReason, static_cast<uint64_t>(revocationReason)));
  content.push_back(ndn::makeBinaryBlock(tlv::PublicKeyHash, publicKeyHash));
  return content;
}

void
recordtlv::decodeRecordContent(const Block& recordContent, state::State& state)
{
  recordContent.parse();
  for (const auto &item : recordContent.elements()) {
    switch (item.type()) {
      case tlv::PublicKeyHash:
        state.m_publicKeyHash.resize(item.value_size());
        std::memcpy(state.m_publicKeyHash.data(), item.value(), item.value_size());
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

void
recordtlv::decodeRecordContent2(const Block& recordContent, 
                                ndn::span<const uint8_t>& publicKeyHash,
                                uint64_t& revocationTimestamp,
                                tlv::ReasonCode& revocationReason,
                                uint64_t& notBefore)
{
  recordContent.parse();
  for (const auto &item : recordContent.elements()) {
    switch (item.type()) {
      case tlv::PublicKeyHash:
        publicKeyHash = ndn::make_span<const uint8_t>(item.value(), item.value_size());
        break;
      case tlv::RevocationTimestamp:
        revocationTimestamp = readNonNegativeInteger(item);
        break;
      case tlv::NotBefore:
        notBefore = readNonNegativeInteger(item);
        break;
      case tlv::RevocationReason:
        revocationReason = static_cast<tlv::ReasonCode>(readNonNegativeInteger(item));
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

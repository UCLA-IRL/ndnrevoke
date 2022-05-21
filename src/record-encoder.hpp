#ifndef NDNREVOKE_RECORD_ENCODER_HPP
#define NDNREVOKE_RECORD_ENCODER_HPP

#include "revocation-common.hpp"
#include "state.hpp"
#include <ndn-cxx/security/key-chain.hpp>
#include "ndn-cxx/util/span.hpp"
namespace ndnrevoke {
namespace recordtlv {

Block
encodeRecordContent(const std::vector<uint8_t>& publicKeyHash, const tlv::ReasonCode revocationReason);

Block
encodeRecordContent2(ndn::span<const uint8_t> publicKeyHash, const tlv::ReasonCode revocationReason, uint64_t notBefore);

void
decodeRecordContent(const Block& recordContent, state::State& state);

void
decodeRecordContent2(const Block& recordContent, 
                     ndn::span<const uint8_t>& publicKeyHash,
                     uint64_t& revocationTimestamp, 
                     tlv::ReasonCode& revocationReason, 
                     uint64_t& notBefore);

} // namespace recordtlv
} // namespace ndnrevoke

#endif // NDNREVOKE_RECORD_ENCODER_HPP

#ifndef NDNREVOKE_NACK_ENCODER_HPP
#define NDNREVOKE_NACK_ENCODER_HPP

#include "revocation-common.hpp"
#include "state.hpp"
#include <ndn-cxx/security/key-chain.hpp>

namespace ndnrevoke {
namespace nacktlv {

Block
encodeNackContent(optional<tlv::NackCode> nackCode);

void
decodeNackContent(const Block& nackContent, state::State& state);

} // namespace recordtlv
} // namespace ndncert

#endif // NDNREVOKE_RECORD_ENCODER_HPP

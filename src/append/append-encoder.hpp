#ifndef NDNREVOKE_APPEND_APPEND_ENCODER_HPP
#define NDNREVOKE_APPEND_APPEND_ENCODER_HPP

#include "append/append-common.hpp"
#include "append/handle-client.hpp"
#include <ndn-cxx/security/key-chain.hpp>

namespace ndnrevoke {
namespace appendtlv {

struct AppenderInfo {
  Name remotePrefix;
  Name forwardingHint;
  Name interestName;
  uint64_t nonce;
  ssize_t retryCount;
};


Block
encodeAppendParameters(const Name& prefix, const uint64_t nonce, const Name& forwardingHint = Name());

void
decodeAppendParameters(const Block& params, AppenderInfo& info);

} // namespace appendtlv
} // namespace ndnrevoke

#endif // NDNREVOKE_APPEND_APPEND_ENCODER_HPP
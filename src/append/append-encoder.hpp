#ifndef NDNREVOKE_APPEND_ENCODER_HPP
#define NDNREVOKE_APPEND_ENCODER_HPP

#include "append/append-common.hpp"
#include "append/handle-client.hpp"
#include "append/handle-ct.hpp"
#include <ndn-cxx/security/key-chain.hpp>

namespace ndnrevoke {
namespace appendtlv {

struct AppenderInfo {
  Name remotePrefix;
  Name dataName;
  Name commandForwardingHint;
  Name dataForwardingHint;
  uint64_t nonce;
};

Block
encodeAppendParameters(const Name& prefix, const uint64_t nonce, const Name& forwardingHint);

void
decodeAppendParameters(const Block& params, AppenderInfo& info);

Block
encodeAppendContent(const Name& dataName, const Name& forwardingHint);

void
decodeAppendContent(const Block& content, AppenderInfo& info);

} // namespace appendtlv
} // namespace ndnrevoke

#endif // NDNREVOKE_RECORD_ENCODER_HPP
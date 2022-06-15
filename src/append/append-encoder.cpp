#include "append/append-encoder.hpp"

namespace ndnrevoke {

Block
appendtlv::encodeAppendParameters(const Name& prefix, const uint64_t nonce, const Name& forwardingHint)
{
  Block params(ndn::tlv::ApplicationParameters);
  params.push_back(makeNestedBlock(appendtlv::AppenderPrefix, prefix));
  if (!forwardingHint.empty()) {
    params.push_back(makeNestedBlock(ndn::tlv::ForwardingHint, forwardingHint));
  }
  params.push_back(ndn::makeNonNegativeIntegerBlock(appendtlv::AppenderNonce, nonce));
  params.encode();
  return params;
}

void
appendtlv::decodeAppendParameters(const Block& params, AppenderInfo& info)
{
  params.parse();
  for (const auto &item : params.elements()) {
    switch (item.type()) {
      case appendtlv::AppenderPrefix:
        info.remotePrefix = Name(item.blockFromValue());
        break;
      case ndn::tlv::ForwardingHint:
        info.forwardingHint = Name(item.blockFromValue());
        break;
      case appendtlv::AppenderNonce:
        info.nonce = readNonNegativeInteger(item);
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

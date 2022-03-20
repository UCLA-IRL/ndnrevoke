#include "append/append-encoder.hpp"

namespace ndnrevoke {

Block
appendtlv::encodeAppendParameters(const Name& prefix, const uint64_t nonce, const Name& forwardingHint)
{
  Block params(ndn::tlv::ApplicationParameters);
  params.push_back(makeNestedBlock(tlv::AppenderPrefix, prefix));
  if (!forwardingHint.empty()) {
    params.push_back(makeNestedBlock(ndn::tlv::ForwardingHint, forwardingHint));
  }
  params.push_back(ndn::makeNonNegativeIntegerBlock(tlv::AppenderNonce, nonce));
  params.encode();
  return params;
}

void
appendtlv::decodeAppendParameters(const Block& params, AppenderInfo& info)
{
  params.parse();
  for (const auto &item : params.elements()) {
    switch (item.type()) {
      case tlv::AppenderPrefix:
        info.remotePrefix = Name(item.blockFromValue());
        break;
      case ndn::tlv::ForwardingHint:
        info.commandForwardingHint = Name(item.blockFromValue());
        break;
      case tlv::AppenderNonce:
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

Block
appendtlv::encodeAppendContent(const Name& dataName, const Name& forwardingHint)
{
  Block content(ndn::tlv::Content);
  content.push_back(ndn::makeNestedBlock(tlv::AppenderDataName, dataName));
  if (!forwardingHint.empty()) {
    content.push_back(makeNestedBlock(ndn::tlv::ForwardingHint, forwardingHint));
  }
  content.push_back(ndn::makeNestedBlock(ndn::tlv::ForwardingHint, forwardingHint));
  content.encode();
  return content;
}

void
appendtlv::decodeAppendContent(const Block& content, AppenderInfo& info)
{
  content.parse();
  for (const auto &item : content.elements()) {
    switch (item.type()) {
      case tlv::AppenderDataName:
        info.dataName = Name(item.blockFromValue());
        break;
      case ndn::tlv::ForwardingHint:
        info.dataForwardingHint = Name(item.blockFromValue());
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

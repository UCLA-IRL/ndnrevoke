#include "append/options.hpp"

namespace ndnrevoke::append {
namespace tlv = appendtlv;
NDN_LOG_INIT(ndnrevoke.append);

std::shared_ptr<Interest>
ClientOptions::makeNotification(const Name& topic)
{
  auto notification = std::make_shared<Interest>(Name(topic).append("notify"));
  // notification parameter: m_prefix, [m_forwardingHint], nonce
  Block params(ndn::tlv::ApplicationParameters);
  params.push_back(makeNestedBlock(appendtlv::AppenderPrefix, getPrefix()));
  if (!getForwardingHint().empty()) {
    params.push_back(makeNestedBlock(ndn::tlv::ForwardingHint, getForwardingHint()));
  }
  params.push_back(ndn::makeNonNegativeIntegerBlock(appendtlv::AppenderNonce, getNonce()));
  params.encode();
  notification->setApplicationParameters(params);
  return notification;
}

const Name
ClientOptions::makeInterestFilter(const Name& topic)
{
  return Name(getPrefix()).append("msg").append(topic)
                          .appendNumber(getNonce());
}

std::shared_ptr<Data>
ClientOptions::makeSubmission(const Name& topic, const std::list<Data>& dataList)
{
  // Data: /<m_prefix>/msg/<topic>/<nonce>
  Name name = Name(getPrefix()).append("msg").append(topic)
                               .appendNumber(getNonce());
  auto data = std::make_shared<Data>(name);
  Block content(ndn::tlv::Content);
  int dataCount = 0;
  for (auto& item : dataList) {
    dataCount++;
    content.push_back(item.wireEncode());
  }
  content.encode();
  data->setContent(content);
  return data;
}

std::list<AppendStatus>
ClientOptions::praseAck(const Data& data)
{ 
  auto content = data.getContent();
  content.parse();
  std::list<AppendStatus> statusList;
  for (const auto &item : content.elements()) {
    switch (item.type()) {
      case tlv::AppendStatusCode:
        statusList.push_back(static_cast<AppendStatus>(readNonNegativeInteger(item)));
        break;
      default:
        if (ndn::tlv::isCriticalType(item.type())) {
          NDN_THROW(std::runtime_error("Unrecognized TLV Type: " + std::to_string(item.type())));
        }
        else {
          // ignore
        }
        break;
    }
  }
  return statusList;
}

std::shared_ptr<ClientOptions>
CtOptions::praseNotification(const Interest& notification)
{
  // Interest: <topic>/<nonce>/<paramDigest>
  // <topic> should be /<ct-prefix>/append

  Name prefix;
  uint64_t nonce = appendtlv::InvalidNonce;
  Name fwHint;
  auto params = notification.getApplicationParameters();
  params.parse();
  for (const auto &item : params.elements()) {
    switch (item.type()) {
      case appendtlv::AppenderPrefix:
        prefix = Name(item.blockFromValue());
        break;
      case ndn::tlv::ForwardingHint:
        fwHint = Name(item.blockFromValue());
        break;
      case appendtlv::AppenderNonce:
        nonce = readNonNegativeInteger(item);
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
  if (fwHint.empty()) {
    return std::make_shared<ClientOptions>(prefix, nonce);    
  }
  else {
    return std::make_shared<ClientOptions>(prefix, nonce, fwHint);
  }
}

std::shared_ptr<Interest>
CtOptions::makeFetcher(ClientOptions& client)
{
  Name name = Name(client.getPrefix()).append("msg").append(m_topic)
                                      .appendNumber(client.getNonce());
  auto fetcher = std::make_shared<Interest>(name);
  auto fwHint = client.getForwardingHint();
  if (!fwHint.empty()) {
    fetcher->setForwardingHint({fwHint});
  }
  return fetcher;
}

std::shared_ptr<Data>
CtOptions::makeNotificationAck(ClientOptions& client,
                               const std::list<AppendStatus>& statusList)
{
  auto notification = client.makeNotification(m_topic);
  auto data = std::make_shared<Data>(notification->getName());
  // acking notification
  Block content(ndn::tlv::Content);
  for (auto& status : statusList) {
    content.push_back(ndn::makeNonNegativeIntegerBlock(tlv::AppendStatusCode, static_cast<uint64_t>(status)));
  }
  content.encode();
  data->setContent(content);
  return data;
}


} // namespace ndnrevoke::append
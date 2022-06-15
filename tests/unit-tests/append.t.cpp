#include "append/handle-ct.hpp"
#include "append/handle-client.hpp"
#include "append/append-encoder.hpp"
#include "test-common.hpp"

namespace ndnrevoke {
namespace tests {

using namespace append;
using ndn::util::DummyClientFace;
using ndn::security::verifySignature;

BOOST_FIXTURE_TEST_SUITE(TestAppend, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(AppendHandleCTNotify)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  auto identity2 = addIdentity(Name("/ndn/site1/abc"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  HandleCt handleCt(identity.getName(), face, m_keyChain);

  auto topic = Name(identity.getName()).append("append");
  handleCt.listenOnTopic(topic, nullptr);
  advanceClocks(time::milliseconds(20), 60);

  auto nonce = ndn::random::generateSecureWord64();
  Interest notification(Name(topic).append("notify"));

  // better to separate into a specific encoder
  // notification parameter: m_prefix, [m_forwardingHint], nonce
  auto param = appendtlv::encodeAppendParameters(identity2.getName(), nonce);
  param.encode();
  notification.setApplicationParameters(param);

  face.receive(notification);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(handleCt.m_nonceMap.size(), 1);
}

BOOST_AUTO_TEST_CASE(AppendHandleCTCommand)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  auto identity2 = addIdentity(Name("/ndn/site1/abc"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  HandleCt handleCt(identity.getName(), face, m_keyChain);

  auto topic = Name(identity.getName()).append("append");
  handleCt.listenOnTopic(topic, [&] (auto i) -> tlv::AppendStatus {
    BOOST_CHECK_EQUAL(i.getName(), cert2.getName());
    BOOST_CHECK_EQUAL(i.getContent().value_size(), cert2.getContent().value_size());
    return tlv::AppendStatus::SUCCESS;
  });
  advanceClocks(time::milliseconds(20), 60);

  auto nonce = ndn::random::generateSecureWord64();
  Interest notification(Name(topic).append("notify"));

  // better to separate into a specific encoder
  // notification parameter: m_prefix, [m_forwardingHint], nonce
  auto param = appendtlv::encodeAppendParameters(identity2.getName(), nonce, Name());
  param.encode();
  notification.setApplicationParameters(param);

  handleCt.onNotification(notification);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(handleCt.m_nonceMap.find(nonce)->second.interestName, notification.getName());

  // // /ndn/site1/abc/msg/ndn/append/%94U%B3h%3BJ%40%8B
  auto dataName = Name("/abc/d");

  Interest submissionFetcher(Name(identity2.getName()).append("msg")
                                           .append(topic).appendNumber(nonce));
  Data submission(submissionFetcher.getName());
  Block content(ndn::tlv::Content);
  content.push_back(cert2.wireEncode());
  content.encode();

  submission.setContent(content);
  submission.setFreshnessPeriod(10_s);
  m_keyChain.sign(submission, ndn::signingByIdentity(identity2));

  handleCt.onSubmissionData(submissionFetcher, submission);
  advanceClocks(time::milliseconds(20), 60);
}

BOOST_AUTO_TEST_CASE(AppendHandleClient)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  auto identity2 = addIdentity(Name("/ndn/site1/abc"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  HandleClient client(identity2.getName(), face, m_keyChain);

  Data data("/ndn/site1/abc/def");
  static const std::string str("Hello, world!");
  data.setContent(ndn::make_span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()), str.size()));
  m_keyChain.sign(data, ndn::signingByIdentity(identity2));
  BOOST_CHECK_EQUAL(client.m_nonceMap.size(), 0);
  client.appendData(Name("/ndn/append"), {data});
  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK_EQUAL(client.m_nonceMap.size(), 1);
  uint64_t nonce = client.m_nonceMap.begin()->first;
  Interest submissionFetcher(Name(identity2.getName()).append("msg").append(identity.getName())
                                           .appendNumber(nonce));
  face.receive(submissionFetcher);
  advanceClocks(time::milliseconds(20), 60);
  // should not be erased
  BOOST_CHECK_EQUAL(client.m_nonceMap.size(), 1);
}

BOOST_AUTO_TEST_CASE(AppendHandleClientStatus)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  auto identity2 = addIdentity(Name("/ndn/site1/abc"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  HandleClient client(identity2.getName(), face, m_keyChain);

  BOOST_CHECK_EQUAL(client.m_nonceMap.size(), 0);
  uint64_t nonce = ndn::random::generateSecureWord64();
  client.m_nonceMap.insert({nonce, {Data()}});

  auto notification = client.makeNotification(Name(identity.getName()).append("append"), nonce);
  Data ack(notification->getName());
  ack.setContent(ndn::makeNonNegativeIntegerBlock(tlv::AppendStatusCode, 
                 static_cast<uint64_t>(tlv::AppendStatus::SUCCESS)));
  m_keyChain.sign(ack, ndn::signingByIdentity(identity));
  client.onNotificationAck(nonce, ack);
  BOOST_CHECK_EQUAL(client.m_nonceMap.size(), 0);
}

BOOST_AUTO_TEST_CASE(AppendHandleClientCallback)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  auto identity2 = addIdentity(Name("/ndn/site1/abc"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  HandleClient client(identity2.getName(), face, m_keyChain);

  Data data("/ndn/site1/abc/def");
  static const std::string str("Hello, world!");
  data.setContent(ndn::make_span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()), str.size()));
  m_keyChain.sign(data, ndn::signingByIdentity(identity2));
  
  BOOST_CHECK_EQUAL(client.m_nonceMap.size(), 0);
  client.appendData(Name("/ndn/append"), {data}, 
    [] (auto& i) {
      Block content = i.getContent();
      content.parse();
      BOOST_CHECK_EQUAL(content.elements_size(), 1);
      BOOST_CHECK_EQUAL(content.elements_begin()->type(), tlv::AppendStatusCode);
      BOOST_CHECK_EQUAL(readNonNegativeInteger(*content.elements_begin()),
                        static_cast<uint64_t>(tlv::AppendStatus::SUCCESS));
    }, nullptr, nullptr, nullptr);
  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK_EQUAL(client.m_nonceMap.size(), 1);
  const uint64_t nonce = client.m_nonceMap.begin()->first;
  auto notification = client.makeNotification(Name(identity.getName()).append("append"), nonce);
  Data ack(notification->getName());
  ack.setContent(ndn::makeNonNegativeIntegerBlock(tlv::AppendStatusCode, 
                 static_cast<uint64_t>(tlv::AppendStatus::SUCCESS)));
  m_keyChain.sign(ack, ndn::signingByIdentity(identity));
  client.onNotificationAck(nonce, ack);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(client.m_nonceMap.size(), 0);
  
  client.appendData(Name("/ndn/append"), {data}, nullptr,
    [] (auto& i) {
      Block content = i.getContent();
      content.parse();
      BOOST_CHECK_EQUAL(content.elements_size(), 1);
      BOOST_CHECK_EQUAL(content.elements_begin()->type(), tlv::AppendStatusCode);
      BOOST_CHECK_EQUAL(readNonNegativeInteger(*content.elements_begin()),
                        static_cast<uint64_t>(tlv::AppendStatus::FAILURE_NACK));
    }, nullptr, nullptr);

  BOOST_CHECK_EQUAL(client.m_nonceMap.size(), 1);
  const uint64_t nonce2 = client.m_nonceMap.begin()->first;
  auto notification2 = client.makeNotification(Name(identity.getName()).append("append"), nonce2);
  Data ack2(notification2->getName());
  ack2.setContent(ndn::makeNonNegativeIntegerBlock(tlv::AppendStatusCode, 
                  static_cast<uint64_t>(tlv::AppendStatus::FAILURE_NACK)));
  m_keyChain.sign(ack2, ndn::signingByIdentity(identity));
  client.onNotificationAck(nonce2, ack2);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(client.m_nonceMap.size(), 0);
}

BOOST_AUTO_TEST_SUITE_END() // TestCtModule

} // namespace tests
} // namespace ndnrevoke

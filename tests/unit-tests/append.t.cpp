#include "append/handle-ct.hpp"
#include "append/append-encoder.hpp"
#include "state.hpp"
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
  BOOST_CHECK_EQUAL(handleCt.m_nonceMap.find(nonce)->second.interestName, notification.getName());
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
  handleCt.listenOnTopic(topic, [](auto i) {std::cout << "nice" << std::endl;});
  advanceClocks(time::milliseconds(20), 60);

  auto nonce = ndn::random::generateSecureWord64();
  Interest notification(Name(topic).append("notify"));

  // better to separate into a specific encoder
  // notification parameter: m_prefix, [m_forwardingHint], nonce
  auto param = appendtlv::encodeAppendParameters(identity2.getName(), nonce, Name());
  param.encode();
  notification.setApplicationParameters(param);

  face.receive(notification);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(handleCt.m_nonceMap.find(nonce)->second.interestName, notification.getName());

  // // /ndn/site1/abc/msg/ndn/append/%94U%B3h%3BJ%40%8B
  auto dataName = Name("/abc/d");
  auto commandName = Name(identity2.getName()).append("msg")
                                              .append(topic).appendNumber(nonce);
  Data command(commandName);
  auto content = appendtlv::encodeAppendContent(dataName);
  command.setContent(content);
  command.setFreshnessPeriod(10_s);
  m_keyChain.sign(command, ndn::signingByIdentity(identity2));

  face.receive(command);
  advanceClocks(time::milliseconds(20), 60);

  Data data(dataName);
  static const std::string str("Hello, world!");
  data.setContent(reinterpret_cast<const uint8_t*>(str.data()), str.size());
  m_keyChain.sign(data, ndn::signingByIdentity(identity2));
  face.receive(data);
  advanceClocks(time::milliseconds(20), 60);
}

BOOST_AUTO_TEST_SUITE_END() // TestRkModule

} // namespace tests
} // namespace ndnrevoke

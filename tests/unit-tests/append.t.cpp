#include "append/ct.hpp"
#include "append/client.hpp"
#include "test-common.hpp"
#include <iostream>

namespace ndnrevoke {
namespace tests {
namespace tlv = appendtlv;
using namespace append;
using ndn::util::DummyClientFace;
using ndn::security::verifySignature;

BOOST_FIXTURE_TEST_SUITE(TestAppend, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(AppendCtStateNotify)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  saveCertificate(identity, "tests/unit-tests/config-files/trust-anchor.ndncert");

  auto identity2 = addSubCertificate(Name("/ndn/site1/abc"), identity);
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  ndn::ValidatorConfig validator{face};
  Name topic = Name(identity.getName()).append("append");
  validator.load("tests/unit-tests/config-files/trust-schema.conf");

  Ct ct(identity.getName(), topic, face, m_keyChain, validator);
  ct.listen(nullptr);
  advanceClocks(time::milliseconds(20), 60);

  // better to separate into a specific encoder
  // notification parameter: m_prefix, [m_forwardingHint], nonce
  uint64_t nonce = ndn::random::generateSecureWord64();
  ClientOptions clientOps(identity2.getName(), topic, nonce, nullptr, nullptr);
  face.receive(*clientOps.makeNotification());
  advanceClocks(time::milliseconds(20), 60);
}

BOOST_AUTO_TEST_CASE(AppendCtStateFetch)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  saveCertificate(identity, "tests/unit-tests/config-files/trust-anchor.ndncert");

  auto identity2 = addSubCertificate(Name("/ndn/site2/abc"), identity);
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  ndn::ValidatorConfig validator{face};
  Name topic = Name(identity.getName()).append("append");
  uint64_t nonce = ndn::random::generateSecureWord64();
  validator.load("tests/unit-tests/config-files/trust-schema.conf");

  Ct ct(identity.getName(), topic, face, m_keyChain, validator);
  ct.listen([cert2] (auto i) -> tlv::AppendStatus {
    BOOST_CHECK_EQUAL(i.getName(), cert2.getName());
    BOOST_CHECK_EQUAL(i.getContent().value_size(), cert2.getContent().value_size());
    return tlv::AppendStatus::SUCCESS;
  });
  advanceClocks(time::milliseconds(20), 60);

  ClientOptions clientOps(identity2.getName(), topic, nonce,
                          nullptr, nullptr);
  face.receive(*clientOps.makeNotification());
  advanceClocks(time::milliseconds(20), 60);

  auto submission = clientOps.makeSubmission({cert2});
  m_keyChain.sign(*submission, ndn::signingByIdentity(identity2));
  face.receive(*submission);
  advanceClocks(time::milliseconds(20), 60);
  face.receive(cert2);
  advanceClocks(time::milliseconds(20), 60);
}

BOOST_AUTO_TEST_CASE(AppendHandleClientCallback)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  saveCertificate(identity, "tests/unit-tests/config-files/trust-anchor.ndncert");

  auto identity2 = addSubCertificate(Name("/ndn/site3/abc"), identity);
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  DummyClientFace face2(io, m_keyChain, {true, true});
  ndn::ValidatorConfig validator{face};
  Name topic = Name(identity.getName()).append("append");
  validator.load("tests/unit-tests/config-files/trust-schema.conf");

  Client Client(identity2.getName(), face2, m_keyChain, validator);
  Data appData("/ndn/site3/abc/appData");
  const std::string str("Hello, world!");
  appData.setContent(make_span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()), str.size()));
  m_keyChain.sign(appData, ndn::signingByIdentity(identity2));

  Ct ct(identity.getName(), topic, face, m_keyChain, validator);
  ct.listen([appData] (auto i) -> tlv::AppendStatus {
    BOOST_CHECK_EQUAL(i.getName(), appData.getName());
    BOOST_CHECK_EQUAL(i.getContent().value_size(), appData.getContent().value_size());
    return tlv::AppendStatus::SUCCESS;
  });
  advanceClocks(time::milliseconds(20), 60);

  uint64_t nonce = Client.appendData(topic, {appData}, 
    [] (auto&&, auto& i) {
      Block content = i.getContent();
      content.parse();
      BOOST_CHECK_EQUAL(content.elements_size(), 1);
      BOOST_CHECK_EQUAL(content.elements_begin()->type(), tlv::AppendStatusCode);
      BOOST_CHECK_EQUAL(readNonNegativeInteger(*content.elements_begin()),
                        static_cast<uint64_t>(tlv::AppendStatus::SUCCESS));
    }, nullptr);
  advanceClocks(time::milliseconds(20), 60);

  ClientOptions clientOps(identity2.getName(), topic, nonce,
                          nullptr, nullptr);
  auto submission = clientOps.makeSubmission({appData});
  m_keyChain.sign(*submission, ndn::signingByIdentity(identity2));
  CtOptions ctOps(topic);
  auto ack = ctOps.makeNotificationAck(clientOps, {tlv::AppendStatus::SUCCESS});
  m_keyChain.sign(*ack, ndn::signingByIdentity(identity));

  face.receive(*clientOps.makeNotification());
  advanceClocks(time::milliseconds(20), 60);
  face.receive(*submission);
  advanceClocks(time::milliseconds(20), 60);
  face.receive(cert2);
  advanceClocks(time::milliseconds(20), 60);
  face2.receive(*ack);
  advanceClocks(time::milliseconds(20), 60);
}

BOOST_AUTO_TEST_SUITE_END() // TestCtModule

} // namespace tests
} // namespace ndnrevoke

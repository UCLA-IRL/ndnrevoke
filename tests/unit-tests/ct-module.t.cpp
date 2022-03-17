#include "ct-module.hpp"
#include "state.hpp"
#include "test-common.hpp"

namespace ndnrevoke {
namespace tests {

using namespace ct;
using ndn::util::DummyClientFace;
using ndn::security::verifySignature;

BOOST_FIXTURE_TEST_SUITE(TestCtModule, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(Initialization)
{
  DummyClientFace face(io, m_keyChain, {true, true});
  CtModule ct(face, m_keyChain, "tests/unit-tests/config-files/config-ct-1", "ct-storage-memory");
  BOOST_CHECK_EQUAL(ct.getCtConf().ctPrefix, Name("/ndn"));

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(ct.m_registeredPrefixHandles.size(), 1); // removed local discovery registration
  BOOST_CHECK_EQUAL(ct.m_interestFilterHandles.size(), 3);  // two record zones: /ndn/site1, /ndn/site2, one submision prefix
}

BOOST_AUTO_TEST_CASE(HandleQueryAndRecord)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  auto identity2 = addIdentity(Name("/ndn/site1/abc"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  CtModule ct(face, m_keyChain, "tests/unit-tests/config-files/config-ct-1", "ct-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  auto recordName = cert2.getName();
  recordName.set(Certificate::KEY_COMPONENT_OFFSET, Name::Component("REVOKE"));
  recordName.append("self");
  Interest interest(recordName);
  interest.setCanBePrefix(true);

  state::State state(cert2, m_keyChain);
  state.setRevocationReason(tlv::ReasonCode::KEY_COMPROMISE);
  state.setPublisher(Name::Component("self"));
  auto record = state.genOwnerRecord(key2.getName(), 100_h);

  face.receive(*state.genSubmissionInterest(Name("/ndn"), *record, key2.getName()));
  advanceClocks(time::milliseconds(20), 60);

  face.onSendData.connect([&](const Data& response) {
    BOOST_CHECK(verifySignature(response, cert2));
    state::State state2(cert2.getName(), m_keyChain);
    state2.getRecord(record::Record(response));
    BOOST_CHECK(state.isRevoked());
  });
  face.receive(interest);
  advanceClocks(time::milliseconds(20), 60);
}

BOOST_AUTO_TEST_CASE(HandleQueryAndNack)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  auto identity2 = addIdentity(Name("/ndn/site1/abc"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  CtModule ct(face, m_keyChain, "tests/unit-tests/config-files/config-ct-1", "ct-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  auto recordName = cert2.getName();
  recordName.set(Certificate::KEY_COMPONENT_OFFSET, Name::Component("REVOKE"));
  recordName.append("self");
  Interest interest(recordName);
  interest.setCanBePrefix(true);

  state::State state(cert2, m_keyChain);

  face.receive(*state.genSubmissionInterest(Name("/ndn"), cert2, key2.getName()));
  advanceClocks(time::milliseconds(20), 60);

  face.onSendData.connect([&](const Data& response) {
    BOOST_CHECK(verifySignature(response, cert));
    BOOST_CHECK_EQUAL(response.getContentType(), ndn::tlv::ContentType_Nack);
    state::State state1(cert2.getName(), m_keyChain);
    state1.getNack(nack::Nack(response));
    BOOST_CHECK(!state1.isRevoked());
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(state1.m_nackCode.value()), 
                      static_cast<uint64_t>(tlv::NackCode::NOT_REVOKED));
  });
  face.receive(interest);
  advanceClocks(time::milliseconds(20), 60);
}

BOOST_AUTO_TEST_SUITE_END() // TestRkModule

} // namespace tests
} // namespace ndnrevoke

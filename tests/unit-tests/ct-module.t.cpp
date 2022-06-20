#include "ct-module.hpp"
#include "test-common.hpp"
#include "revoker.hpp"
#include "checker.hpp"

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
  BOOST_CHECK_EQUAL(ct.m_handle.m_registeredPrefixHandles.size(), 1); // removed local discovery registration
  BOOST_CHECK_EQUAL(ct.m_handle.m_interestFilterHandles.size(), 2);
}

BOOST_AUTO_TEST_CASE(HandleQueryAndRecord)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  saveCertificate(identity, "tests/unit-tests/config-files/trust-anchor.ndncert");

  auto identity2 = addSubCertificate(Name("/ndn/site1/abc"), identity);
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  CtModule ct(face, m_keyChain, "tests/unit-tests/config-files/config-ct-1", "ct-storage-memory");
  ndn::ValidatorConfig validator{face};
  validator.load("tests/unit-tests/config-files/trust-schema.conf");
  revoker::Revoker revoker(m_keyChain);
  checker::Checker checker(face, validator);

  ct.m_storage->addData(cert2);
  advanceClocks(time::milliseconds(20), 60);
  auto record = revoker.revokeAsOwner(cert2, tlv::ReasonCode::KEY_COMPROMISE, 
                                      time::toUnixTimestamp(time::system_clock::now()), 1_s);
  ct.m_storage->addData(*record);
  checker.doOwnerCheck(Name("/ndn/LEDGER"), cert2, nullptr, 
    [record] (auto&&, auto& i) {
      BOOST_CHECK_EQUAL(i.getName(), record->getName());
      BOOST_CHECK(i.getReason() == tlv::ReasonCode::KEY_COMPROMISE);
    },
    nullptr
  );
  advanceClocks(time::milliseconds(20), 60);
  face.receive(cert2);
  advanceClocks(time::milliseconds(20), 60);
}

BOOST_AUTO_TEST_CASE(HandleQueryAndNack)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  saveCertificate(identity, "tests/unit-tests/config-files/trust-anchor.ndncert");

  auto identity2 = addSubCertificate(Name("/ndn/site2/abc"), identity);
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  CtModule ct(face, m_keyChain, "tests/unit-tests/config-files/config-ct-1", "ct-storage-memory");
  ndn::ValidatorConfig validator{face};
  validator.load("tests/unit-tests/config-files/trust-schema.conf");
  revoker::Revoker revoker(m_keyChain);
  checker::Checker checker(face, validator);

  advanceClocks(time::milliseconds(20), 60);
  checker.doOwnerCheck(Name("/ndn/LEDGER"), cert2, 
    [cert2] (auto&&, auto& i) {
      BOOST_CHECK_EQUAL(i.getCertName(), cert2.getName());
    },
    nullptr, nullptr
  );
  advanceClocks(time::milliseconds(200), 600);
}

BOOST_AUTO_TEST_SUITE_END() // TestCtModule

} // namespace tests
} // namespace ndnrevoke

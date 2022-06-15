#include "ct-module.hpp"
#include "test-common.hpp"
#include "revoker.hpp"
#include "checker.hpp"

namespace ndnrevoke {
namespace tests {

using namespace ct;
using ndn::util::DummyClientFace;
using ndn::security::verifySignature;

BOOST_FIXTURE_TEST_SUITE(TestCtModuleV2, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(Initialization)
{
  DummyClientFace face(io, m_keyChain, {true, true});
  CtModule ct(face, m_keyChain, "tests/unit-tests/config-files/config-ct-1", "ct-storage-memory");
  BOOST_CHECK_EQUAL(ct.getCtConf().ctPrefix, Name("/ndn"));

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(ct.m_registeredPrefixHandles.size(), 1); // removed local discovery registration
  BOOST_CHECK_EQUAL(ct.m_interestFilterHandles.size(), 2);
}

BOOST_AUTO_TEST_CASE(HandleQueryAndRecordV2)
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

  revoker::Revoker revoker(m_keyChain);
  checker::Checker checker(face);
  auto record = revoker.revokeAsOwner(cert2, tlv::ReasonCode::KEY_COMPROMISE, 
                                      ndn::time::toUnixTimestamp(time::system_clock::now()), 1_s);
  ct.m_storage->addData(*record);
  checker.doOwnerCheck(Name("/ndn/LEDGER"), cert2, nullptr, 
    [cert2] (auto& i) {
        // BOOST_CHECK(verifySignature(i, cert2));
        // BOOST_CHECK_EQUAL(i.getContentType(), ndn::tlv::ContentType_Key);
    },
    nullptr
  );
  advanceClocks(time::milliseconds(20), 60);
}

BOOST_AUTO_TEST_CASE(HandleQueryAndNackV2)
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

  checker::Checker checker(face);
  checker.doOwnerCheck(Name("/ndn/LEDGER"), cert2, 
    [cert] (auto& i) {
        // BOOST_CHECK(verifySignature(i, cert));
        // BOOST_CHECK_EQUAL(i.getContentType(), ndn::tlv::ContentType_Nack);
    },
    nullptr, nullptr
  );
  advanceClocks(time::milliseconds(20), 60);
}

BOOST_AUTO_TEST_SUITE_END() // TestCtModule

} // namespace tests
} // namespace ndnrevoke

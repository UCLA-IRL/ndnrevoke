#include "rk-memory.hpp"
#include "test-common.hpp"

namespace ndnrevoke {
namespace tests {

using namespace rk;

BOOST_FIXTURE_TEST_SUITE(TestRkMemory, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(RevocationStateOperations)
{
  RkMemory storage;

  auto identity1 = addIdentity(Name("/ndn/site1"));
  auto key1 = identity1.getDefaultKey();
  auto cert1 = key1.getDefaultCertificate();

  // add operation
  RevocationState state1;
  state1.rkPrefix = Name("/ndn/rk1");
  state1.status = RevocationStatus::VALID_CERTIFICATE;
  state1.certName = cert1.getName();
  state1.publisherId = Name::Component("self");
  state1.reasonCode = tlv::ReasonCode::INVALID;
  auto buf = Sha256::computeDigest(cert1.getPublicKey());
  state1.publicKeyHash.assign(buf->begin(), buf->end());

  BOOST_CHECK_NO_THROW(storage.addRevocationState(state1));

  // get operation
  auto result = storage.getRevocationState(cert1.getName());
  BOOST_CHECK_EQUAL(state1.certName, result.certName);
  BOOST_CHECK(state1.status == result.status);
  BOOST_CHECK_EQUAL(state1.rkPrefix, result.rkPrefix);
  BOOST_CHECK_EQUAL_COLLECTIONS(state1.publicKeyHash.begin(), state1.publicKeyHash.end(),
                                result.publicKeyHash.begin(), result.publicKeyHash.end());

  // update operation
  RevocationState state2;
  state2.rkPrefix = Name("/ndn/rk1");
  state2.status = RevocationStatus::REVOKED_CERTIFICATE;
  state2.certName = cert1.getName();
  state2.publisherId = Name::Component("self");
  state2.reasonCode = tlv::ReasonCode::SUPERSEDED;
  state2.publicKeyHash.assign(buf->begin(), buf->end());

  storage.updateRevocationState(state2);
  result = storage.getRevocationState(cert1.getName());
  BOOST_CHECK(state2.status == result.status);
  BOOST_CHECK_EQUAL(state2.rkPrefix, result.rkPrefix);

  // another add operation
  auto identity2 = addIdentity(Name("/ndn/site2"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();
  RevocationState state3;
  state3.rkPrefix = Name("/ndn/rk2");
  state3.status = RevocationStatus::REVOKED_CERTIFICATE;
  state3.certName = cert2.getName();
  state3.publisherId = Name::Component("self");
  state2.reasonCode = tlv::ReasonCode::SUPERSEDED;
  auto buf2 = Sha256::computeDigest(cert2.getPublicKey());
  state3.publicKeyHash.assign(buf2->begin(), buf2->end());
  storage.addRevocationState(state3);

  // list operation
  auto allStates = storage.listAllRevocationStates();
  BOOST_CHECK_EQUAL(allStates.size(), 2);

  storage.deleteRevocationState(cert1.getName());
  allStates = storage.listAllRevocationStates();
  BOOST_CHECK_EQUAL(allStates.size(), 1);
}

BOOST_AUTO_TEST_SUITE_END() // TestRkMemory

} // namespace tests
} // namespace ndnrevoke

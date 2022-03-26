#include "storage/ct-memory.hpp"
#include "test-common.hpp"

namespace ndnrevoke {
namespace tests {

using namespace ct;

BOOST_FIXTURE_TEST_SUITE(TestCtMemory, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(CertificateStateOperations)
{
  CtMemory storage;

  auto identity1 = addIdentity(Name("/ndn/site1"));
  auto key1 = identity1.getDefaultKey();
  auto cert1 = key1.getDefaultCertificate();

  // add operation
  CertificateState state1;
  state1.ctPrefix = Name("/ndn/ct1");
  state1.status = CertificateStatus::VALID_CERTIFICATE;
  state1.cert = cert1;
  state1.publisherId = Name::Component("self");
  state1.reasonCode = tlv::ReasonCode::INVALID;
  auto buf = Sha256::computeDigest(cert1.getPublicKey());
  state1.publicKeyHash.assign(buf->begin(), buf->end());

  BOOST_CHECK_NO_THROW(storage.addCertificateState(state1));

  // get operation
  auto result = storage.getCertificateState(cert1.getName());
  BOOST_CHECK_EQUAL(state1.cert, result.cert);
  BOOST_CHECK(state1.status == result.status);
  BOOST_CHECK_EQUAL(state1.ctPrefix, result.ctPrefix);
  BOOST_CHECK_EQUAL_COLLECTIONS(state1.publicKeyHash.begin(), state1.publicKeyHash.end(),
                                result.publicKeyHash.begin(), result.publicKeyHash.end());

  // update operation
  CertificateState state2;
  state2.ctPrefix = Name("/ndn/ct1");
  state2.status = CertificateStatus::REVOKED_CERTIFICATE;
  state2.cert = cert1;
  state2.publisherId = Name::Component("self");
  state2.reasonCode = tlv::ReasonCode::SUPERSEDED;
  state2.publicKeyHash.assign(buf->begin(), buf->end());

  storage.updateCertificateState(state2);
  result = storage.getCertificateState(cert1.getName());
  BOOST_CHECK(state2.status == result.status);
  BOOST_CHECK_EQUAL(state2.ctPrefix, result.ctPrefix);

  // another add operation
  auto identity2 = addIdentity(Name("/ndn/site2"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();
  CertificateState state3;
  state3.ctPrefix = Name("/ndn/ct2");
  state3.status = CertificateStatus::REVOKED_CERTIFICATE;
  state3.cert = cert2;
  state3.publisherId = Name::Component("self");
  state3.reasonCode = tlv::ReasonCode::SUPERSEDED;
  auto buf2 = Sha256::computeDigest(cert2.getPublicKey());
  state3.publicKeyHash.assign(buf2->begin(), buf2->end());
  storage.addCertificateState(state3);

  // list operation
  auto allStates = storage.listAllCertificateStates();
  BOOST_CHECK_EQUAL(allStates.size(), 2);

  storage.deleteCertificateState(cert1.getName());
  allStates = storage.listAllCertificateStates();
  BOOST_CHECK_EQUAL(allStates.size(), 1);
}

BOOST_AUTO_TEST_SUITE_END() // TestCtMemory

} // namespace tests
} // namespace ndnrevoke

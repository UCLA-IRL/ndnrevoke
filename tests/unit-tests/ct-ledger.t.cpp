#include "storage/ct-storage-ledger.hpp"
#include "record-encoder.hpp"
#include "test-common.hpp"
#include "ndn-cxx/security/validator-null.hpp"

namespace ndnrevoke {
namespace tests {

using namespace ct;

class LedgerTest: public IdentityManagementFixture {
  public:
    LedgerTest() :
            identity1(addIdentity(Name("/ndn/site1"))),
            key1(identity1.getDefaultKey()),
            cert1(key1.getDefaultCertificate()) {
        m_keyChain.createIdentity("/ndn/ct1");
        auto config = cert_ledger::Config::CustomizedConfig("/ndn/broadcast/cert-ledger-dag", "/ndn/ct1",
                                                            "/tmp/ct-ledger-test" + std::to_string(ndn::random::generateWord32()));
        storage = make_shared<CtStorageLedger>(*config, m_keyChain, dummyFace,
                                               std::make_shared<security::ValidatorNull>());
    }
  public:
    util::DummyClientFace dummyFace;
    std::shared_ptr<CtStorageLedger> storage;
    Identity identity1;
    const Key &key1;
    const Certificate &cert1;
};

BOOST_FIXTURE_TEST_SUITE(TestCtLedger, LedgerTest)

BOOST_AUTO_TEST_CASE(CertificateStateOperations)
{

  // add operation
  CertificateState state1;
  state1.ctPrefix = Name("/ndn/ct1");
  state1.status = CertificateStatus::VALID_CERTIFICATE;
  state1.cert = cert1;
  state1.publisherId = Name::Component("self");
  state1.reasonCode = tlv::ReasonCode::INVALID;
  auto buf = Sha256::computeDigest(cert1.getPublicKey());
  state1.publicKeyHash.assign(buf->begin(), buf->end());

  BOOST_CHECK_NO_THROW(storage->addCertificateState(state1));

  storage->listAllCertificateStates();

  // get operation
  auto result = storage->getCertificateState(cert1.getName());
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

  auto recordName = record::Record::getRevocationRecordPrefix(state2.cert.getName()).append(state2.publisherId);
  state2.record.setName(recordName);
  state2.record.setContent(recordtlv::encodeRecordContent(state2.publicKeyHash, state2.reasonCode));
  m_keyChain.sign(state2.record, security::signingWithSha256());

  storage->updateCertificateState(state2);
  result = storage->getCertificateState(cert1.getName());
  BOOST_CHECK(state2.status == result.status);
  BOOST_CHECK_EQUAL(state2.ctPrefix, result.ctPrefix);

  // another add operation
  auto identity2 = addIdentity(Name("/ndn/site2"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();
  CertificateState state3;
  state3.ctPrefix = Name("/ndn/ct1");
  state3.status = CertificateStatus::REVOKED_CERTIFICATE;
  state3.cert = cert2;
  state3.publisherId = Name::Component("self");
  state3.reasonCode = tlv::ReasonCode::SUPERSEDED;
  auto buf2 = Sha256::computeDigest(cert2.getPublicKey());
  state3.publicKeyHash.assign(buf2->begin(), buf2->end());

  recordName = record::Record::getRevocationRecordPrefix(state3.cert.getName()).append(state3.publisherId);
  state3.record.setName(recordName);
  state3.record.setContent(recordtlv::encodeRecordContent(state3.publicKeyHash, state3.reasonCode));
  m_keyChain.sign(state3.record, security::signingWithSha256());

  storage->addCertificateState(state3);

  // list operation
  auto allStates = storage->listAllCertificateStates();
  BOOST_CHECK_EQUAL(allStates.size(), 2);

  BOOST_CHECK_THROW(storage->deleteCertificateState(cert1.getName()), std::exception);
}

BOOST_AUTO_TEST_CASE(AddBadCertState) {
    // add operation
    CertificateState state1;
    state1.ctPrefix = Name("/ndn/ct2");
    state1.status = CertificateStatus::VALID_CERTIFICATE;
    state1.cert = cert1;
    state1.publisherId = Name::Component("self");
    state1.reasonCode = tlv::ReasonCode::INVALID;
    auto buf = Sha256::computeDigest(cert1.getPublicKey());
    state1.publicKeyHash.assign(buf->begin(), buf->end());

    BOOST_CHECK_THROW(storage->addCertificateState(state1), std::exception);
}

BOOST_AUTO_TEST_SUITE_END() // TestCtLedger

} // namespace tests
} // namespace ndnrevoke

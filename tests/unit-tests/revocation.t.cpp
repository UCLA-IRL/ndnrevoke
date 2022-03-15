#include "record.hpp"
#include "record-encoder.hpp"
#include "revocation-state.hpp"
#include "test-common.hpp"

namespace ndnrevoke {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestRevocationRecord, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(RecordFormat)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  
  state::State genState(cert, m_keyChain);
  auto newRecord = genState.genIssuerRecord(key.getName());
  
  ndn::printHex(std::cout, genState.m_publicKeyHash);
  std::cout << std::endl << *newRecord << std::endl;

  auto newRecordBlock = newRecord->wireEncode();
  newRecordBlock.parse();
  record::Record getRecord(newRecordBlock);
  state::State getState(cert, m_keyChain);
  getState.getRecord(getRecord);

  ndn::printHex(std::cout, getState.m_publicKeyHash);
  std::cout << std::endl << getRecord << std::endl;

  BOOST_CHECK_EQUAL(std::memcmp(genState.m_publicKeyHash.data(), getState.m_publicKeyHash.data(), genState.m_publicKeyHash.size()), 0);
}
BOOST_AUTO_TEST_SUITE_END() // TestRevocationRecord

} // namespace tests
} // namespace ndnrevoke
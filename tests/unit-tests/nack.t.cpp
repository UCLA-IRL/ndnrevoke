#include "record.hpp"
#include "record-encoder.hpp"
#include "state.hpp"
#include "test-common.hpp"

namespace ndnrevoke {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestNack, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(NackFormat)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  
  state::State genState(cert, m_keyChain);
  genState.setPublisher(Name::Component("self"));
  genState.setNackCode(tlv::NackCode::NOT_REVOKED);
  auto newNack = genState.genNack(key.getName());
//   std::cout << std::endl << *newNack << std::endl;

  auto newNackBlock = newNack->wireEncode();
  newNackBlock.parse();
  nack::Nack getNack(newNackBlock);
//   std::cout << getNack << std::endl;
  state::State getState(cert, m_keyChain);
  getState.getNack(getNack);

  BOOST_ASSERT(getState.m_nackCode.has_value());
  const uint64_t nackCode = static_cast<uint64_t>(tlv::NackCode::NOT_REVOKED);
  BOOST_CHECK_EQUAL(static_cast<uint64_t>(getState.m_nackCode.value()), nackCode);
}
BOOST_AUTO_TEST_SUITE_END() // TestRevocationRecord

} // namespace tests
} // namespace ndnrevoke
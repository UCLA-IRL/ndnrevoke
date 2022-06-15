#include "storage/ct-memory.hpp"
#include "test-common.hpp"

namespace ndnrevoke {
namespace tests {

using namespace ct;

BOOST_FIXTURE_TEST_SUITE(TestCtMemory, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(BasicOps)
{
  CtMemory storage;

  auto identity1 = addIdentity(Name("/ndn/site1"));
  auto key1 = identity1.getDefaultKey();
  auto cert1 = key1.getDefaultCertificate();

  // add operation
  BOOST_CHECK_NO_THROW(storage.addData(cert1));

  // get operation
  Data result;
  BOOST_CHECK_NO_THROW(result = storage.getData(cert1.getName()));
  BOOST_CHECK_EQUAL(cert1, result);

  // delete operation
  BOOST_CHECK_NO_THROW(storage.deleteData(cert1.getName()));
}

BOOST_AUTO_TEST_SUITE_END() // TestCtMemoryV2

} // namespace tests
} // namespace ndnrevoke

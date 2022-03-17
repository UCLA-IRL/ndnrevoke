#include "rk-configuration.hpp"
#include "test-common.hpp"

namespace ndnrevoke {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestConfig, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(RkConfigFile)
{
  rk::RkConfig config;
  config.load("tests/unit-tests/config-files/config-rk-1");
  BOOST_CHECK_EQUAL(config.rkPrefix, "/ndn");
  BOOST_CHECK_EQUAL(config.recordFreshnessPeriod, time::seconds(864000));
  BOOST_CHECK_EQUAL(config.nackFreshnessPeriod, time::seconds(864000));
  BOOST_CHECK_EQUAL(config.recordZones.size(), 2);
  BOOST_CHECK_EQUAL(config.recordZones.front(), Name("/ndn/site1"));
  BOOST_CHECK_EQUAL(config.recordZones.back(), Name("/ndn/site2"));
}

BOOST_AUTO_TEST_CASE(RkConfigFileWithErrors)
{
  rk::RkConfig config;
  // nonexistent file
  BOOST_CHECK_THROW(config.load("tests/unit-tests/config-files/Nonexist"), std::runtime_error);
  // missing record zones
  BOOST_CHECK_THROW(config.load("tests/unit-tests/config-files/config-rk-2"), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END() // TestConfig

} // namespace tests
} // namespace ndnrevoke

#ifndef NDNREVOKE_REVOCATION_COMMON_HPP
#define NDNREVOKE_REVOCATION_COMMON_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>

#include <ndn-cxx/data.hpp>
#include <ndn-cxx/encoding/block.hpp>
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/name.hpp>
#include <ndn-cxx/security/certificate.hpp>
#include <ndn-cxx/util/exception.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/optional.hpp>
#include <ndn-cxx/util/sha256.hpp>
#include <ndn-cxx/util/time.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/assert.hpp>
#include <boost/noncopyable.hpp>
#include <boost/property_tree/ptree.hpp>

#include "ndnrevoke-config.hpp"

#ifdef NDNREVOKE_HAVE_TESTS
#define NDNREOVKE_VIRTUAL_WITH_TESTS virtual
#define NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PROTECTED public
#define NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE public
#define NDNREVOKE_PROTECTED_WITH_TESTS_ELSE_PRIVATE protected
#else
#define NDNREVOKE_VIRTUAL_WITH_TESTS
#define NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PROTECTED protected
#define NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE private
#define NDNREVOKE_PROTECTED_WITH_TESTS_ELSE_PRIVATE private
#endif

namespace ndnrevoke {

using ndn::Block;
using ndn::Buffer;
using ndn::Data;
using ndn::Interest;
using ndn::Name;
using ndn::SignatureInfo;
using ndn::security::Certificate;
using ndn::util::Sha256;
using ndn::span;
using ndn::optional;
using ndn::nullopt;
using JsonSection = boost::property_tree::ptree;

using ndn::make_span;

namespace time = ndn::time;
using namespace ndn::time_literals;
using namespace std::string_literals;

namespace tlv {

enum : uint32_t {
  RevocationTimestamp = 201,
  PublicKeyHash = 202,
  RevocationReason = 203,
  NackReason = 204,
  NotBefore = 205
};

// Revocation Reason
enum class ReasonCode : uint64_t {
  UNSPECIFIED = 0,
  KEY_COMPROMISE = 1,
  CA_COMPROMISE = 2,

  SUPERSEDED = 4,
  INVALID = 99,
};

// Nack Reason
enum class NackCode : uint64_t {
  NOT_REVOKED = 0
};

} // namespace tlv
} // namespace ndnrevoke

#endif // NDNREVOKE_REVOCATION_COMMON_HPP

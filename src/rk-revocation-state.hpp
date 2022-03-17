#ifndef NDNREVOKE_RK_REVOCATION_STATE_HPP
#define NDNREVOKE_RK_REVOCATION_STATE_HPP

#include "revocation-common.hpp"
#include "record.hpp"

#include <array>

namespace ndnrevoke {

// RevocationStatus in RevocationKeeper
enum class RevocationStatus : uint64_t {
  NOTINITIALIZED = 0,
  VALID_CERTIFICATE = 1,
  REVOKED_CERTIFICATE = 2
};

/**
 * @brief Convert RevocationStatus to string.
 */
std::string
statusToString(RevocationStatus status);

/**
 * @brief Convert RevocationStatus to string.
 */
RevocationStatus
statusFromBlock(const Block& block);

// Tianyuan: I name it to Record Keeper (will have a better name in future)
// Revocation Authority is an absolutely bad name.
namespace rk {

/**
 * @brief Represents a certificate request instance kept by the CA.
 *
 * ChallengeModule should take use of RequestState.ChallengeState to keep the challenge state.
 */
struct RevocationState
{
  /**
   * @brief The certificate name regarding the revocation.
   */
  Name certName; // used as primary key (when needed)
  /**
   * @brief The RK that the state is under.
   */
  Name rkPrefix;
  /**
   * @brief The type of the state.
   */
  RevocationStatus status = RevocationStatus::NOTINITIALIZED;
  /**
   * @brief The reason of revocation.
   */
  tlv::ReasonCode reasonCode = tlv::ReasonCode::INVALID;
  /**
   * @brief The publisher id regarding the revocation (if any).
   */
  Name::Component publisherId;
  /**
   * @brief The public key hash of the corresponding certificate.
   */
  std::vector<uint8_t> publicKeyHash;
  /**
   * @brief The last Initialization Vector used by the other side's AES encryption.
   */
  uint64_t revocationTimestamp;

  // should have a revocation record if the certificate is revoked
  record::Record record;
};

std::shared_ptr<RevocationState>
makeRevocationState(record::Record& record);

std::shared_ptr<RevocationState>
makeRevocationState(Certificate& cert);

std::ostream&
operator<<(std::ostream& os, const RevocationState& request);

} // namespace rk
} // namespace ndnrevoke

#endif // NDNREVOKE_RK_REVOCATION_STATE_HPP

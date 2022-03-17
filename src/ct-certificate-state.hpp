#ifndef NDNREVOKE_CT_CERTIFICATE_STATE_HPP
#define NDNREVOKE_CT_CERTIFICATE_STATE_HPP

#include "revocation-common.hpp"
#include "record.hpp"

#include <array>

namespace ndnrevoke {

// RevocationStatus in RevocationKeeper
enum class CertificateStatus : uint64_t {
  NOTINITIALIZED = 0,
  VALID_CERTIFICATE = 1,
  REVOKED_CERTIFICATE = 2
};

/**
 * @brief Convert RevocationStatus to string.
 */
std::string
statusToString(CertificateStatus status);

/**
 * @brief Convert RevocationStatus to string.
 */
CertificateStatus
statusFromBlock(const Block& block);

namespace ct {

/**
 * @brief Represents a certificate request instance kept by the CA.
 *
 * ChallengeModule should take use of RequestState.ChallengeState to keep the challenge state.
 */
struct CertificateState
{
  /**
   * @brief The certificate name regarding the revocation.
   */
  Name certName; // used as primary key (when needed)
  /**
   * @brief The CT that the state is under.
   */
  Name ctPrefix;
  /**
   * @brief The type of the state.
   */
  CertificateStatus status = CertificateStatus::NOTINITIALIZED;
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

std::shared_ptr<CertificateState>
makeCertificateState(record::Record& record);

std::shared_ptr<CertificateState>
makeCertificateState(Certificate& cert);

std::ostream&
operator<<(std::ostream& os, const CertificateState& state);

} // namespace ct
} // namespace ndnrevoke

#endif // NDNREVOKE_CT_REVOCATION_STATE_HPP

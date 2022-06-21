#include <iostream>

#include "revocation-common.hpp"
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
namespace ndnrevoke::util {

/**
 * Copied from ndn-cxx
 * @brief Load a TLV-encoded, base64-armored object from a file named @p filename.
 */
template<typename T>
T
loadFromFile(const std::string& filename)
{
  try {
    if (filename == "-") {
      return ndn::io::loadTlv<T>(std::cin, ndn::io::BASE64);
    }

    std::ifstream file(filename);
    if (!file) {
      NDN_THROW(std::runtime_error("Cannot open '" + filename + "'"));
    }
    return ndn::io::loadTlv<T>(file, ndn::io::BASE64);
  }
  catch (const ndn::io::Error& e) {
    NDN_THROW_NESTED(std::runtime_error("Cannot load '" + filename +
                                        "': malformed TLV or not in base64 format (" + e.what() + ")"));
  }
}

/**
 * Modified from ndn-cxx
 */
ndn::security::Certificate
getCertificateFromPib(ssize_t& nStep,
                      const ndn::security::pib::Pib& pib, const Name& name,
                      bool isIdentityName, bool isKeyName, bool isCertName);

Name
captureKeyName(ssize_t& nStep, ndn::security::pib::Identity& identity);

Name
captureCertName(ssize_t& nStep, ndn::security::pib::Key& key);

} // namespace ndnrevoke::util
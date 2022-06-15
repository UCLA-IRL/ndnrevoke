#include "append/handle-client.hpp"
#include "append/handle-ct.hpp"
#include "revoker.hpp"
#include "checker.hpp"

#include <iostream>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/scheduler.hpp>

namespace ndnrevoke {
namespace client {

NDN_LOG_INIT(ndnrevoke.example);

static ndn::Face face;
static ndn::KeyChain keyChain;
static ndn::Scheduler scheduler(face.getIoService());
static const ndn::time::milliseconds CHECKOUT_INTERVAL = 10_ms;
static const Name ledgerPrefix = Name("/ndn/edu/ucla/v2/LEDGER");

Certificate
issueCertificate(const Certificate& ownerCert, const Name& issuerCertName, 
                 const Name::Component& issuer)
{
  Certificate newCert;
  ndn::security::MakeCertificateOptions opts;
  ndn::security::SigningInfo signer;

  opts.issuerId = issuer;
  opts.version = time::toUnixTimestamp(time::system_clock::now()).count();
  opts.freshnessPeriod = 1_h;
  opts.validity = ownerCert.getValidityPeriod();
  signer.setSigningCertName(issuerCertName);
  newCert = keyChain.makeCertificate(ownerCert, signer, opts);
  NDN_LOG_TRACE("new cert got signed: " << newCert);
  return newCert;
}

static int
main(int argc, char* argv[])
{
  ndn::security::pib::Identity issuerId, ownerId;
  try {
    issuerId = keyChain.getPib().getIdentity(Name("/ndn/edu/ucla/v2/cs"));
  }
  catch (const std::exception&) {
    issuerId = keyChain.createIdentity(Name("/ndn/edu/ucla/v2/cs"));
  }

  try {
    ownerId = keyChain.getPib().getIdentity(Name("/ndn/edu/ucla/v2/cs/producer"));
  }
  catch (const std::exception&) {
    ownerId = keyChain.createIdentity(Name("/ndn/edu/ucla/v2/cs/producer"));
  }

  auto issuerKey = issuerId.getDefaultKey();
  auto issuerCert = issuerKey.getDefaultCertificate();
  auto ownerKey = ownerId.getDefaultKey();

  // use issuer to sign owner
  auto ownerCert = issueCertificate(ownerKey.getDefaultCertificate(), issuerCert.getName(),
                                    Name::Component("cs-signer"));
  // init append client for revoker and callbacks for checker
  append::HandleClient client(ownerId.getName(), face, keyChain);
  checker::Checker checker(face, "trust-schema.conf");


  // scheduled record appending after prefix registeration
  scheduler.schedule(CHECKOUT_INTERVAL, [&] {
    revoker::Revoker revoker(keyChain);
    auto ownerRecord = revoker.revokeAsOwner(ownerCert, tlv::ReasonCode::SUPERSEDED);
    auto issuerRecord = revoker.revokeAsIssuer(ownerCert, tlv::ReasonCode::SUPERSEDED);
    Name appendPrefix = Name(ledgerPrefix).append("append");
    client.appendData(appendPrefix, {*ownerRecord, *issuerRecord},
      [&] (auto& i) {
          Block content = i.getContent();
          content.parse();
          for (auto elem : content.elements()) {
            uint64_t status = readNonNegativeInteger(elem);
            NDN_LOG_INFO("Append status [SUCCESS]: " << append::statusToString(static_cast<appendtlv::AppendStatus>(status)));
          }
      },
      [&] (auto& i) {
          Block content = i.getContent();
          content.parse();
          for (auto elem : content.elements()) {
            uint64_t status = readNonNegativeInteger(elem);
            NDN_LOG_INFO("Append status [FAILURE]: " << append::statusToString(static_cast<appendtlv::AppendStatus>(status)));
          }
      },
      [] (auto&&) {
          NDN_LOG_INFO("Append Timeout");
      },
      [] (auto&&, auto& i) {
          NDN_LOG_INFO("Append Nack: " << i.getReason());
      }
    );
   }
  );

  // query for record
  scheduler.schedule(CHECKOUT_INTERVAL * 2, [&] {
   checker.doOwnerCheck(ledgerPrefix, ownerCert, 
    [] (auto& i) {
      // on valid, should be a nack data
    },
    [] (auto& i) {
      // on revoked, should be a record
      // NDN_LOG_INFO("Record Data: " << i);
    },
    [] (auto i) {
      // NDN_LOG_INFO("Failure Reason: " << i);
    });

    checker.doIssuerCheck(ledgerPrefix, ownerCert, 
    [] (auto& i) {
      // on valid, should be a nack data
    },
    [] (auto& i) {
      // on revoked, should be a record
      // NDN_LOG_INFO("Record Data: " << i);
    },
    [] (auto i) {
      // NDN_LOG_INFO("Failure Reason: " << i);
    });
  }
  );

  face.processEvents();
  return 0;
}

} // namespace client
} // namespace ndnrevoke

int
main(int argc, char* argv[])
{
  return ndnrevoke::client::main(argc, argv);
}

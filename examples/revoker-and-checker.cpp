#include "append/client.hpp"
#include "revoker.hpp"
#include "checker.hpp"

#include <iostream>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/scheduler.hpp>

namespace ndnrevoke {
namespace client {

static ndn::Face face;
static ndn::KeyChain keyChain;
static ndn::Scheduler scheduler(face.getIoService());
static const ndn::time::milliseconds CHECKOUT_INTERVAL = 10_ms;
static const Name ledgerPrefix = Name("/example/LEDGER");

static int
main(int argc, char* argv[])
{
  ndn::security::pib::Identity issuerId, ownerId;
  issuerId = keyChain.getPib().getIdentity(Name("/example"));
  ownerId = keyChain.getPib().getIdentity(Name("/example/testApp"));

  auto issuerKey = issuerId.getDefaultKey();
  auto issuerCert = issuerKey.getDefaultCertificate();
  auto ownerKey = ownerId.getDefaultKey();
  auto ownerCert = ownerKey.getDefaultCertificate();
  // init append client for revoker and callbacks for checker

  ndn::ValidatorConfig validator{face};
  Name topic = Name(ownerId.getName()).append("append");
  validator.load("trust-schema.conf");

  append::ClientState clientState(ownerId.getName(), face, keyChain, validator);
  checker::Checker checker(face, "trust-schema.conf");

  face.setInterestFilter(ndn::security::extractIdentityFromCertName(ownerCert.getName()),
    [ownerCert] (auto&&...) {
      face.put(ownerCert);
    },
    [] (auto& prefix, auto& reason) {
      std::cerr << "ERROR: Failed to register prefix '" << prefix
      << "' with the local forwarder (" << reason << ")\n";
      face.shutdown();
    });

  // scheduled record appending after prefix registeration
  scheduler.schedule(CHECKOUT_INTERVAL, [&] {
    revoker::Revoker revoker(keyChain);
    auto ownerRecord = revoker.revokeAsOwner(ownerCert, tlv::ReasonCode::SUPERSEDED);
    auto issuerRecord = revoker.revokeAsIssuer(ownerCert, tlv::ReasonCode::SUPERSEDED);
    Name appendPrefix = Name(ledgerPrefix).append("append");
    clientState.appendData(appendPrefix, {*ownerRecord, *issuerRecord},
      [&] (auto&&, auto& ack) {
          Block content = ack.getContent();
          content.parse();
          for (auto elem : content.elements()) {
            uint64_t status = readNonNegativeInteger(elem);
            std::cout << "Append status: " << appendtlv::statusToString(static_cast<appendtlv::AppendStatus>(status))
                      << std::endl;
          }
      },
      [] (auto&&, auto& error) {
          std::cout << error << std::endl;
      }
    );
   }
  );

  // query for record
  scheduler.schedule(CHECKOUT_INTERVAL * 2, [&] {
   checker.doOwnerCheck(ledgerPrefix, ownerCert, 
    [] (auto& i) {
      // on valid, should be a nack data
      std::cout << i << std::endl;
    },
    [] (auto& i) {
      // on revoked, should be a record
      std::cout << i << std::endl;
    },
    [] (auto&&, auto& i) {
      std::cout << "Failed because of: " << i << std::endl;
    });

    checker.doIssuerCheck(ledgerPrefix, ownerCert, 
    [] (auto& i) {
      // on valid, should be a nack data
      std::cout << i << std::endl;
    },
    [] (auto& i) {
      // on revoked, should be a record
      std::cout << i << std::endl;
    },
    [] (auto&&, auto& i) {
      std::cout << "Failed because of: " << i << std::endl;
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

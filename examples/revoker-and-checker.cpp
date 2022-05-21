#include "append/handle-client.hpp"
#include "append/handle-ct.hpp"
#include "revoker.hpp"
#include "checker.hpp"

#include <iostream>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/scheduler.hpp>

namespace ndnrevoke {
namespace client {

NDN_LOG_INIT(ndnrevoke.example);

static ndn::Face face;
static ndn::KeyChain keyChain;
static ndn::Scheduler scheduler(face.getIoService());
static const ndn::time::milliseconds CHECKOUT_INTERVAL = 10_ms;
static const Name ledgerPrefix = Name("/ndn/edu/ucla/v2/LEDGER");

static int
main(int argc, char* argv[])
{
  ndn::security::pib::Identity identity;
  try {
    identity = keyChain.getPib().getIdentity(Name("/ndn/edu/ucla/v2/cs/producer"));
  }
  catch (const std::exception&) {
    identity = keyChain.createIdentity(Name("/ndn/edu/ucla/v2/cs/producer"));
  }

  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();


  // init append client for revoker and callbacks for checker
  append::HandleClient client(identity.getName(), face, keyChain);
  checker::Checker checker(face);


  // scheduled record appending after prefix registeration
  scheduler.schedule(CHECKOUT_INTERVAL, [&] {
    revoker::Revoker revoker(keyChain);
    auto record = revoker.revokeAsOwner(cert, tlv::ReasonCode::SUPERSEDED, 
                                        time::toUnixTimestamp(time::system_clock::now()).count());
    Name appendPrefix = Name(ledgerPrefix).append("append");
    client.appendData(appendPrefix, {*record},
      [&] (auto& i) {
          Block content = i.getContent();
          content.parse();
          uint64_t status = readNonNegativeInteger(*content.elements_begin());
          NDN_LOG_INFO("Append status [SUCCESS]: " << append::statusToString(static_cast<tlv::AppendStatus>(status)));
      },
      [&] (auto& i) {
          Block content = i.getContent();
          content.parse();
          uint64_t status = readNonNegativeInteger(*content.elements_begin());
          NDN_LOG_INFO("Append status [FAILURE]: " << append::statusToString(static_cast<tlv::AppendStatus>(status)));
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
   checker.doOwnerCheck(ledgerPrefix, cert, 
    [] (auto& i) {
      // on valid, should be a nack data
      NDN_LOG_INFO("Nack Data: " << i);
    },
    [] (auto& i) {
      // on revoked, should be a record
      NDN_LOG_INFO("Record Data: " << i);
    },
    [] (auto i) {
      NDN_LOG_INFO("Failure Reason: " << i);
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

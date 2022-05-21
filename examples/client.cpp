#include "append/handle-client.hpp"
#include "append/handle-ct.hpp"
#include "state.hpp"

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

static int
main(int argc, char* argv[])
{
  ndn::security::pib::Identity identity;
  try {
    identity = keyChain.getPib().getIdentity(Name("/ndn/site1/abc"));
  }
  catch (const std::exception&) {
    identity = keyChain.createIdentity(Name("/ndn/site1/abc"));
  }

  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  append::HandleClient client(identity.getName(), face, keyChain);

  // scheduled record appending after prefix registeration
  // this shall fail with FAILURE_NX_CERT.
  // because the cert data must be appended before the revocation record
  scheduler.schedule(CHECKOUT_INTERVAL, [&] {
    state::State state(cert, keyChain);
    state.setRevocationReason(tlv::ReasonCode::SUPERSEDED);
    auto record = state.genOwnerRecord(key.getName());
    client.appendData(Name("/ndn/append"), {*record}, nullptr,
        [] (auto& i) {
          Block content = i.getContent();
          content.parse();

          if (content.elements_size() != 1) {
            NDN_LOG_DEBUG("Elements size not as expected");
            return;
          }
          uint64_t status = readNonNegativeInteger(*content.elements_begin());
          if (static_cast<tlv::AppendStatus>(status) == tlv::AppendStatus::FAILURE_NX_CERT) {
            NDN_LOG_DEBUG("Failed as expected");
          }
          else {
            NDN_LOG_INFO("Failed or succeeded not as expected");
          }
          NDN_LOG_INFO("Append status: " << append::statusToString(static_cast<tlv::AppendStatus>(status)));
        }, nullptr, nullptr
    );
   }
  );

  //append cert & revocation reason 
  scheduler.schedule(CHECKOUT_INTERVAL, [&] {
    state::State state(cert, keyChain);
    state.setRevocationReason(tlv::ReasonCode::SUPERSEDED);
    auto record = state.genOwnerRecord(key.getName());
    client.appendData(Name("/ndn/append"), {cert, *record},
        [] (auto& i) {
          Block content = i.getContent();
          content.parse();

          if (content.elements_size() != 2) {
            NDN_LOG_DEBUG("Elements size not as expected");
            return;
          }

          ssize_t count = 0;
          for (auto& iter: content.elements()) {
            uint64_t status = readNonNegativeInteger(iter);
            NDN_LOG_INFO("Append status for data " << count << ": " 
                          << append::statusToString(static_cast<tlv::AppendStatus>(status)));
            count++;
          }
        }, nullptr, nullptr, nullptr
    );
   }
  );

  //query for certificate
  scheduler.schedule(CHECKOUT_INTERVAL *2, [&] {
    //construct interest
    std::cout << "Constructing Cert Interest" << std::endl;
    Interest certInterest(cert.getName());
    certInterest.setForwardingHint({Name("/ndn/CT")});
    face.expressInterest(certInterest, [] (auto& interest, auto& data) {
      std::cout << "Received Data " << data << std::endl;
    }, nullptr, [] (auto& Interest) {
        std::cout << "Timeout" << std::endl;
      }
    );
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

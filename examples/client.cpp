/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
 *
 * This file is part of ndncert, a certificate management system based on NDN.
 *
 * ndncert is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndncert is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndncert, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndncert authors and contributors.
 */

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
    client.appendData(Name("/ndn/ct1/append"), {*record}, nullptr,
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

  scheduler.schedule(CHECKOUT_INTERVAL, [&] {
    state::State state(cert, keyChain);
    state.setRevocationReason(tlv::ReasonCode::SUPERSEDED);
    auto record = state.genOwnerRecord(key.getName());
    client.appendData(Name("/ndn/ct1/append"), {cert, *record},
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

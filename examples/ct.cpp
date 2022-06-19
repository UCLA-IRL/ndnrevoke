#include "ct-module.hpp"

#include <iostream>
#include <chrono>
#include <deque>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>

namespace ndnrevoke {
namespace ct {

static ndn::Face face;
static ndn::KeyChain keyChain;

static int
main(int argc, char* argv[])
{
  CtModule ct(face, keyChain, "ct.config");
  face.processEvents();
  return 0;
}

} // namespace ct
} // namespace ndnrevoke

int
main(int argc, char* argv[])
{
  return ndnrevoke::ct::main(argc, argv);
}
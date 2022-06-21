#include "checker.hpp"
#include "util.hpp"

#include <boost/asio.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>

#include <chrono>
#include <deque>
#include <iostream>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>

namespace ndnrevoke::checker {

static ndn::Face face;
static ndn::ValidatorConfig validator{face};
static ndn::KeyChain keyChain;
static std::shared_ptr<Checker> checker;
static ssize_t nStep = 0;
static bool finishIssuerCheck = false;
static bool finishOwnerCheck = false;

static void
handleSignal(const boost::system::error_code& error, int signalNum)
{
  if (error) {
    return;
  }
  const char* signalName = ::strsignal(signalNum);
  std::cerr << "Exiting on signal ";
  if (signalName == nullptr) {
    std::cerr << signalNum;
  }
  else {
    std::cerr << signalName;
  }
  std::cerr << std::endl;
  face.getIoService().stop();
  exit(1);
}

static void
joinCheckings()
{
  if (finishIssuerCheck && finishOwnerCheck) {
    std::cerr << "Revocation checkings finished.\nQuit.\n";
    exit(1);
  }
  else {
    // has not finish, wait for the other
  }
}

static void
checkRecords(const Certificate& cert, const Name& ledgerName,
             ndn::security::Validator& validator, bool isPretty)
{
  checker = std::make_shared<Checker>(face, validator);
  checker->doOwnerCheck(ledgerName, cert, 
    [isPretty] (auto&&, auto& i) {
      // on valid, should be a nack data
      if (isPretty) {
        std::cerr << i << std::endl;
      }
      finishOwnerCheck = true;
      std::cerr << "Certificate owner has NOT revoked this certificate!\n";
      joinCheckings();
    },
    [isPretty] (auto&&, auto& i) {
      // on revoked, should be a record
      if (isPretty) {
        std::cerr << i << std::endl;
      }
      finishOwnerCheck = true;
      std::cerr << "Certificate owner has revoked this certificate!\n";
      joinCheckings();
    },
    [] (auto&&, auto& i) {
      std::cerr << "ERROR: Failed because of: " << i << std::endl;
      finishOwnerCheck = true;
      joinCheckings();
    }
  );

  checker->doIssuerCheck(ledgerName, cert, 
    [isPretty] (auto&&, auto& i) {
      // on valid, should be a nack data
      if (isPretty) {
        std::cerr << i << std::endl;
      }
      finishIssuerCheck = true;
      std::cerr << "Certificate issuer has NOT revoked this certificate!\n";
      joinCheckings();
    },
    [isPretty] (auto&&, auto& i) {
    // on revoked, should be a record
      if (isPretty) {
        std::cerr << i << std::endl;
      }
      finishIssuerCheck = true;
      std::cerr << "Certificate issuer has revoked this certificate!\n";
      joinCheckings();
    },
    [] (auto&&, auto& i) {
      finishIssuerCheck = true;
      std::cerr << "ERROR: Failed because of: " << i << std::endl;
      joinCheckings();
    }
  );
}
static int
main(int argc, char* argv[])
{
  boost::asio::signal_set terminateSignals(face.getIoService());
  terminateSignals.add(SIGINT);
  terminateSignals.add(SIGTERM);
  terminateSignals.async_wait(handleSignal);

  std::string validatorFilePath;
  std::string certFilePath;
  std::string certName;
  std::string certIdentity;

  namespace po = boost::program_options;
  std::string name;
  bool isIdentityName = false;
  bool isKeyName = false;
  bool isFileName = false;
  bool isPretty = false;
  std::string ledgerPrefix;

  po::options_description description(
    "Usage: ndnrevoke-checker [-h] [-p] [-b NOTBEFORE] [-l LEDGERPREFIX] [-d VALIDATOR ] [-i|-k|-f] [-n] NAME\n"
    "\n"
    "Options");
  description.add_options()
    ("help,h",           "produce help message")
    ("pretty,p",         po::bool_switch(&isPretty), "display the revocation record or nack in human readable format")
    ("identity,i",       po::bool_switch(&isIdentityName),
                         "treat the NAME argument as an identity name (e.g., /ndn/edu/ucla/alice)")
    ("key,k",            po::bool_switch(&isKeyName),
                         "treat the NAME argument as a key name (e.g., /ndn/edu/ucla/alice/ksk-123456789)")
    ("file,f",           po::bool_switch(&isFileName),
                         "treat the NAME argument as the name of a file containing a base64-encoded "
                         "certificate, '-' for stdin")
    ("name,n",           po::value<std::string>(&name),
                         "unless overridden by -i/-k/-f, the name of the certificate to be revoked "
                         "(e.g., /ndn/edu/ucla/KEY/cs/alice/ksk-1234567890/ID-CERT/%FD%FF%FF%FF%FF%FF%FF%FF)")
    ("ledger-prefix,l",   po::value<std::string>(&ledgerPrefix),
                         "ledger prefix (e.g., /example/LEDGER)")
    ("validator,d",      po::value<std::string>(&validatorFilePath),
                         "the file path to load the ndn-cxx validator (e.g., trust-schema.conf)")
    ;

  po::positional_options_description p;
  p.add("name", 1);

  po::variables_map vm;
  try {
    po::store(po::command_line_parser(argc, argv).options(description).positional(p).run(), vm);
    po::notify(vm);
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << "\n\n"
              << description << std::endl;
    return 2;
  }

  if (vm.count("help") > 0) {
    std::cout << description << std::endl;
    return 0;
  }

  if (vm.count("name") == 0) {
    std::cerr << "ERROR: you must specify a name" << std::endl;
    return 2;
  }

  int nIsNameOptions = isIdentityName + isKeyName + isFileName;
  if (nIsNameOptions > 1) {
    std::cerr << "ERROR: at most one of '--identity', '--key', "
                 "or '--file' may be specified" << std::endl;
    return 2;
  }

  ndn::security::Certificate certificate;
  if (isFileName) {
    certificate = util::loadFromFile<ndn::security::Certificate>(name);
  }
  else {
    certificate = util::getCertificateFromPib(nStep, keyChain.getPib(), name,
                    isIdentityName, isKeyName, nIsNameOptions == 0);
  }
  std::cerr << "Checking " << certificate.getName() << "...\n";
  validator.load(validatorFilePath);
  checkRecords(certificate, Name(ledgerPrefix), validator, isPretty);
  face.processEvents();
  return 0;
}
} // namespace ndncert::ca

int
main(int argc, char* argv[])
{
  return ndnrevoke::checker::main(argc, argv);
}
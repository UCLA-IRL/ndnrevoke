#include "revoker.hpp"
#include "append/client.hpp"
#include "util.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
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

namespace ndnrevoke::revoker {

static ndn::Face face;
static ndn::ValidatorConfig validator{face};
static ndn::KeyChain keyChain;
static std::shared_ptr<Revoker> revoker;
static std::shared_ptr<append::Client> client;
static ssize_t nStep = 0;

using registerContinuation = std::function<void(void)>; // continuation after registering prefix

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
registerPrefix(const Certificate& signerCert, const registerContinuation contiunation)
{
	Name revokerPrefix = ndn::security::extractIdentityFromCertName(signerCert.getName());
  face.registerPrefix(
    revokerPrefix,
    [signerCert, contiunation] (const Name& name) {
      // provide revoker's own certificate
      // notice: this only register FIB to Face, not NFD.
      face.setInterestFilter(signerCert.getName(),
			  [signerCert] (auto&&, const auto& i) {
					 face.put(signerCert);
				}
			);
			contiunation();
    },
    [revokerPrefix] (auto&&, const auto& reason) { 
			std::cerr << "Prefix registeration of " << revokerPrefix << "failed.\n"
			          << "Reason: " << reason << "\nQuit\n";
		}
  );	
}

static void
submitRecord(const Name& revokerPrefix, const Name& ledgerName, const std::shared_ptr<Data>& data)
{
	std::cerr << "Submitting record to "<< ledgerName << "...\n";
	// use record KeyLocator as prefix
	client = std::make_shared<append::Client>(revokerPrefix, face, keyChain, validator);

	std::string errorMsg = "ERROR: Ledger cannot log the submitted record because of ";
	client->appendData(Name(ledgerName).append("append"), {*data},
		[errorMsg] (auto&&, auto& ack) {
			using aa = appendtlv::AppendStatus;
			Block content = ack.getContent();
			content.parse();
			for (auto elem : content.elements()) {
				uint64_t status = readNonNegativeInteger(elem);
				switch (static_cast<aa>(status)) {
					case aa::SUCCESS:
						std::cerr << "Submission Success!\n";
						break;
					case aa::FAILURE_NACK:
						std::cerr << errorMsg
											<< "Ledger Interest NACK\n";
						break;
					case aa::FAILURE_STORAGE:
						std::cerr << errorMsg
											<< "Internal storage error "
											<< "(ledger may have logged the same record)\n";
						break;
					case aa::FAILURE_TIMEOUT:
						std::cerr << errorMsg 
											<< "Ledger Interest timeout\n";
						break;
					case aa::FAILURE_VALIDATION_APP:
						std::cerr << errorMsg 
											<< "Submitted Record does not conform to trust schema\n";
						break;
					case aa::FAILURE_VALIDATION_PROTO:
						std::cerr << errorMsg
											<< "Submission Protocol Data does not conform to trust schema\n";
						break;
					default:
						std::cerr << errorMsg
											<< "Unknown errors\n";
						break;
				}
			}
			std::cerr << "Quit.\n";
			exit(1);
		},
		[errorMsg] (auto&&, auto& error) {
			std::cerr << errorMsg << error.getInfo()
								<< "\nQuit.\n";
			exit(1);
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
	bool isIssuer = false;
  std::string ledgerPrefix;
	std::string reasonStr;
	std::string notBeforeStr;

  po::options_description description(
    "Usage: ndnrevoke-revoker [-h] [-p] [-s] [-r REASON] [-b NOTBEFORE] [-l LEDGERPREFIX] [-d VALIDATOR ][-i|-k|-f] [-n] NAME\n"
    "\n"
    "Options");
  description.add_options()
    ("help,h",           "produce help message")
    ("pretty,p",         po::bool_switch(&isPretty), "display the revocation record in human readable format")
	  ("issuer,s",         po::bool_switch(&isIssuer), "revoke the certificate as the issuer")
    ("identity,i",       po::bool_switch(&isIdentityName),
                         "treat the NAME argument as an identity name (e.g., /ndn/edu/ucla/alice)")
    ("key,k",            po::bool_switch(&isKeyName),
                         "treat the NAME argument as a key name (e.g., /ndn/edu/ucla/alice/ksk-123456789)")
    ("file,f",           po::bool_switch(&isFileName),
                         "treat the NAME argument as the name of a file containing a base64-encoded "
                         "certificate, '-' for stdin")
		("reason,r",         po::value<std::string>(&reasonStr), "revocation reason of the certificate")
    ("not-before,S",     po::value<std::string>(&notBeforeStr),
                         "revocation record validity start date/time in YYYYMMDDhhmmss format (default: now)")
    ("name,n",           po::value<std::string>(&name),
                         "unless overridden by -i/-k/-f, the name of the certificate to be revoked "
                         "(e.g., /ndn/edu/ucla/KEY/cs/alice/ksk-1234567890/ID-CERT/%FD%FF%FF%FF%FF%FF%FF%FF)")
    ("ledger-prefix,l",  po::value<std::string>(&ledgerPrefix),
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

  tlv::ReasonCode reasonCode;
	reasonCode = record::stringToReason(reasonStr);
  if (reasonCode == tlv::ReasonCode::INVALID) {
    std::cerr << "ERROR: the reason is invalid" 
	               "Available reasons are: UNSPECIFIED, KEY_COMPROMISE, "
								 "CA_COMPROMISE, SUPERSEDED\n";
    return 2;
  }


  time::system_clock::TimePoint notBefore;
  if (vm.count("not-before") == 0) {
    notBefore = time::system_clock::now();
  }
  else {
    notBefore = time::fromIsoString(notBeforeStr.substr(0, 8) + "T" + notBeforeStr.substr(8, 6));
  }

	auto certNotBefore = certificate.getValidityPeriod().getPeriod().first;
	auto certNotAfter = certificate.getValidityPeriod().getPeriod().second;
	if (certNotBefore > notBefore || certNotAfter < notBefore)
	{
		std::cerr << "ERROR: the notBefore is outside of certificate ValidityPeriod: "
							<< ndn::time::toString(certNotBefore) << "-"
							<< ndn::time::toString(certNotAfter) << std::endl;
		return 2;		
	}

  revoker = std::make_shared<Revoker>(keyChain);
	std::shared_ptr<Data> recordData;
	std::cerr << "Revoking " << certificate.getName() << "...\n";
	if (isIssuer) {
		recordData = revoker->revokeAsIssuer(certificate, reasonCode,
		                                     ndn::time::toUnixTimestamp(notBefore));
	}
	else {
		recordData = revoker->revokeAsOwner(certificate, reasonCode, 
			                                  ndn::time::toUnixTimestamp(notBefore));
	}

	if (isPretty) {
    std::cout << record::Record(*recordData) << std::endl;
  }
	else {
    using namespace ndn::security::transform;
    bufferSource(recordData->wireEncode()) >> base64Encode(true) >> streamSink(std::cout);
	}

	if (!ledgerPrefix.empty()) {
		Name ledgerName(ledgerPrefix);
		// use record KeyLocator as prefix
		Name keyLocator = recordData->getKeyLocator().value().getName();
		Name revokerPrefix = ndn::security::extractIdentityFromCertName(keyLocator);
		validator.load(validatorFilePath);

    Certificate revokerCert = util::getCertificateFromPib(nStep, keyChain.getPib(), keyLocator,
      false, false, true);
		registerPrefix(revokerCert,
	    [revokerPrefix, ledgerName, recordData]() {
		    submitRecord(revokerPrefix, ledgerName, recordData);
		  }
		);
	}
  face.processEvents();
  return 0;
}
} // namespace ndncert::ca

int
main(int argc, char* argv[])
{
  return ndnrevoke::revoker::main(argc, argv);
}
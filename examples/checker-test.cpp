#include <iostream>
#include <ctime>
#include <filesystem>

#include <experimental/random>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/base64-decode.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/security/transform/stream-source.hpp>

#include "checker.hpp"

namespace ndnrevoke {
namespace client {

NDN_LOG_INIT(ndnrevoke.example);

static ndn::Face face;
static ndn::KeyChain keyChain;
static ndn::Scheduler scheduler(face.getIoService());

static double fetch_time = 0;
static std::vector<ndn::security::Certificate> certStorage;
static std::vector<int> indexSeq;

void
read_sequence(std::string seqFilePath)
{
  std::ifstream file(seqFilePath);
  std::string read;
  std::vector<int> uniqued;
  while (std::getline(file, read)) {
    int certIndex = std::stoul(read);
    indexSeq.push_back(certIndex);
    if (std::find(uniqued.begin(), uniqued.end(), certIndex) == uniqued.end()) {
      uniqued.push_back(certIndex);
    }
  }
  if (certStorage.size() != uniqued.size()) {
    std::cerr << "sequence index " << indexSeq.size()
              << " and cert number " << certStorage.size() << " not match!" << std::endl;
    exit(1);
  }
}

void
read_certs(std::string certDir)
{
  namespace fs = std::filesystem;
  for (auto& certFile : fs::directory_iterator(certDir)) {
    std::string certFilePath = certFile.path().string(); 
    std::ifstream file(certFilePath);
    try {
      if (!file) {
        NDN_THROW(std::runtime_error("Cannot open '" + certFilePath + "'"));
      }
      auto cert = ndn::io::loadTlv<Certificate>(file);
      std::cout << "loaded " << cert.getName() << std::endl;
      certStorage.push_back(cert);
    }
    catch (std::exception& e) {
      NDN_THROW_NESTED(std::runtime_error("Cannot load '" + certFilePath +
                                          "': malformed TLV or not in base64 format (" + e.what() + ")"));
    }
  }
}

void 
test_fetching(Name ledgerPrefix, int intervalSec)
{
  auto seconds = ndn::time::seconds(intervalSec);
  ndn::time::milliseconds baseDelay(seconds);
  for (size_t j = 0; j < certStorage.size(); j++)
  {
    std::cout<<"Remaining tries: "<< certStorage.size() - j << std::endl;
    int randChoice = std::experimental::randint(0, static_cast<int>(certStorage.size() - 1));
    int randDelay = std::experimental::randint(0, static_cast<int>(0.25 * baseDelay.count()));
    Certificate certChoice = certStorage[randChoice];
    std::cout << "Checking Cert: "<< certChoice.getName() << std::endl;
    checker::Checker checker(face);
    struct timespec begin;
    // query for record
    scheduler.schedule(baseDelay + ndn::time::milliseconds(randDelay),
      [&] {
        clock_gettime(CLOCK_REALTIME, &begin);
        checker.doOwnerCheck(ledgerPrefix, certChoice,
          [begin, j] (auto& i) {
            // on valid, should be a nack data
            struct timespec end;
            clock_gettime(CLOCK_REALTIME, &end);
            long sec = end.tv_sec - begin.tv_sec;
            long nsec = end.tv_nsec - begin.tv_nsec;
            double elapsed = sec + nsec * 1e-9;
            fetch_time += elapsed;
            if (j == certStorage.size() - 1) {
              std::cout << "Fetching Time: " << fetch_time / 100.0 << std::endl;
            }
            NDN_LOG_TRACE("Nack Data: " << i);
            face.shutdown();
          },
          [begin, j] (auto& i) {
            // on revoked, should be a record
            struct timespec end;
            clock_gettime(CLOCK_REALTIME, &end);
            long sec = end.tv_sec - begin.tv_sec;
            long nsec = end.tv_nsec - begin.tv_nsec;
            double elapsed = sec + nsec * 1e-9;
            fetch_time += elapsed;
            if (j == certStorage.size() - 1) {
              std::cout << "Fetching Time: "<< fetch_time / 100.0 << std::endl;
            }
            NDN_LOG_TRACE("Record Data: " << i);
            face.shutdown();
          },
          [begin] (auto i) {
            struct timespec end;
            clock_gettime(CLOCK_REALTIME, &end);
            long sec = end.tv_sec - begin.tv_sec;
            long nsec = end.tv_nsec - begin.tv_nsec;
            double elapsed = sec + nsec * 1e-9;
            fetch_time += elapsed;
            NDN_LOG_TRACE("Failure Reason: " << i);
            face.shutdown();
          });
    }
  );
  face.processEvents();
  }
}

static int
main(int argc, char** argv)
{
  namespace po = boost::program_options;
  std::string certDir;
  std::string interval("1");
  std::string ledgerPrefix;
  std::string seqFilePath;
  po::options_description description;
  description.add_options()
    ("help,h", "produce help message")
    ("cert-dir,d", po::value<std::string>(&certDir),
                   "directory name of certificates to be imported")
    ("ledger,l", po::value<std::string>(&ledgerPrefix),
                   "ledger prefix")
    ("sequence,s", po::value<std::string>(&seqFilePath),
                   "sequence file")
    ("interval,i", po::value<std::string>(&interval),
                   "intervals of record fetching");
  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, description), vm);
    po::notify(vm);
  }
  catch (const po::error& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 2;
  }
  catch (const boost::bad_any_cast& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 2;
  }

  if (vm.count("help") != 0) {
    std::cout << "Usage: " << argv[0] << " [options]\n"
              << "\n"
              << description;
    return 0;
  }

  if (vm.count("cert-dir") == 0) {
    std::cerr << "ERROR: you must specify a directory name" << std::endl;
    std::cout << "Usage: " << argv[0] << " [options]\n"
              << "\n"
              << description;
    return 2;
  }

  read_certs(certDir);
  read_sequence(seqFilePath);
  test_fetching(Name(ledgerPrefix), std::stoul(interval));
  return 0;
}

} // namespace client
} // namespace ndnrevoke

int
main(int argc, char* argv[])
{
  return ndnrevoke::client::main(argc, argv);
}

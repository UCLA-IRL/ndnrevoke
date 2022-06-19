#include "error.hpp"

#include <ostream>

namespace ndnrevoke {

std::ostream&
operator<<(std::ostream& os, Error::Code code)
{
  switch (code) {
    case Error::Code::NO_ERROR:
      return os << "No error";
    case Error::Code::TIMEOUT:
      return os << "Timeout";
    case Error::Code::NACK:
      return os << "NACK";
    case Error::Code::VALIDATION_ERROR:
      return os << "Validation error";
    case Error::Code::IMPLEMENTATION_ERROR:
      return os << "Internal implementation error";
    case Error::Code::PROTO_SPECIFIC:
      return os << "Protocol specific error";
  }
  return os << "Unrecognized reason";
}

std::ostream&
operator<<(std::ostream& os, const Error& error)
{
  os << static_cast<Error::Code>(error.getCode());
  if (!error.getInfo().empty()) {
    os << " (" << error.getInfo() << ")";
  }
  return os;
}

} // namespace ndnrevoke

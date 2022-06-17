#include "append/append-common.hpp"

namespace ndnrevoke::appendtlv {

std::string statusToString(AppendStatus status)
{
  switch (status) {
    case AppendStatus::SUCCESS:
      return "Success";
    case AppendStatus::FAILURE_NACK:
      return "FAILURE_NACK";
    case AppendStatus::FAILURE_TIMEOUT:
      return "FAILURE_TIMEOUT";
    case AppendStatus::FAILURE_STORAGE:
      return "FAILURE_STORAGE";
    case AppendStatus::FAILURE_VALIDATION_APP:
      return "FAILURE_VALIDATION_APP";
    case AppendStatus::FAILURE_VALIDATION_PROTO:
      return "FAILURE_VALIDATION_PROTO";
    default:
      return "Unrecognized status";
  }
}

} // namespace ndnrevoke::appendtlv

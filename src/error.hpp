#ifndef NDNREVOKE_ERROR_HPP
#define NDNREVOKE_ERROR_HPP

#include "revocation-common.hpp"

namespace ndnrevoke {
/**
 * @brief Error code and optional detailed error message
 */
class Error
{
public:
  /**
   * @brief Known error codes
   */
  enum Code : uint32_t {
    NO_ERROR             = 0,
    TIMEOUT              = 1,
    NACK                 = 2,
    VALIDATION_ERROR     = 3,
    IMPLEMENTATION_ERROR = 255,
    PROTO_SPECIFIC       = 256 // custom error codes should use >=256
  };

public:
  /**
   * @brief Error, implicitly convertible from an error code and info
   */
  Error(uint32_t code, const std::string& info = "")
    : m_code(code)
    , m_info(info)
  {
  }

  uint32_t
  getCode() const
  {
    return m_code;
  }

  const std::string&
  getInfo() const
  {
    return m_info;
  }

private:
  uint32_t m_code;
  std::string m_info;
};

std::ostream&
operator<<(std::ostream& os, Error::Code code);

std::ostream&
operator<<(std::ostream& os, const Error& error);

} // namespace ndnrevoke

#endif // NDNREVOKE_ERROR_HPP

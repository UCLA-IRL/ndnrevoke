#ifndef NDNREVOKE_APPEND_HANDLE_HPP
#define NDNREVOKE_APPEND_HANDLE_HPP

#include "append/append-common.hpp"
namespace ndnrevoke::append {

class Handle : boost::noncopyable
{
public:
  explicit
  Handle()
  {
  }

  ~Handle();

  Handle&
  handlePrefix(const ndn::RegisteredPrefixHandle& prefix);
  
  Handle&
  handleFilter(const ndn::InterestFilterHandle& filter);

NDNREVOKE_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::list<ndn::RegisteredPrefixHandle> m_registeredPrefixHandles;
  std::list<ndn::InterestFilterHandle> m_interestFilterHandles;
};

} // namespace ndnrevoke::append

#endif // NDNREVOKE_APPEND_HANDLE_HPP

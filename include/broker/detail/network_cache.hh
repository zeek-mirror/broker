#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>

#include <caf/actor.hpp>
#include <caf/event_based_actor.hpp>
#include <caf/io/middleman.hpp>
#include <caf/openssl/manager.hpp>
#include <caf/optional.hpp>
#include <caf/result.hpp>

#include "broker/fwd.hh"
#include "broker/logger.hh"
#include "broker/network_info.hh"

namespace broker::detail {

/// Maps any number of network addresses to remote actor handles. Actors can be
/// reachable under several addresses for multiple reasons. For example,
/// "127.0.0.1" and "localhost" point to the same network endpoint or an actor
/// can get published to more than one port.
class network_cache {
public:
  network_cache(caf::event_based_actor* selfptr);

  void set_use_ssl(bool use_ssl);

  /// Either returns an actor handle immediately if the entry is cached or
  /// queries the middleman actor and responds later via response promise.
  caf::result<caf::actor> fetch(const network_info& x);

  template <class OnResult, class OnError>
  void fetch(const network_info& x, OnResult f, OnError g) {
    using namespace caf;
    auto y = find(x);
    if (y) {
      f(*y);
      return;
    }
    self->request(mm_, infinite, connect_atom_v, x.address, x.port)
      .then(
        [=](const node_id&, strong_actor_ptr& res,
            std::set<std::string>& ifs) mutable {
          if (!ifs.empty()) {
            error err{sec::unexpected_actor_messaging_interface};
            g(err);
          } else if (res == nullptr) {
            error err{sec::no_actor_published_at_port};
            g(err);
          } else {
            auto hdl = actor_cast<actor>(std::move(res));
            hdls_.emplace(x, hdl);
            addrs_.emplace(hdl, x);
            f(std::move(hdl));
          }
        },
        [=](error& err) mutable { g(err); });
  }

  template <class OnResult, class OnError>
  void fetch(const caf::actor& x, OnResult f, OnError g) {
    using namespace caf;
    auto y = find(x);
    if (y) {
      f(*y);
      return;
    }
    self->request(mm_, infinite, atom::get_v, x.node())
      .then(
        [=](const node_id&, std::string& address, uint16_t port) mutable {
          network_info result{std::move(address), port};
          hdls_.emplace(result, x);
          addrs_.emplace(x, result);
          f(std::move(result));
        },
        [=](error& err) mutable { g(std::move(err)); });
  }

  /// Returns the handle associated to `x`, if any.
  caf::optional<caf::actor> find(const network_info& x);

  /// Returns all known network addresses for `x`.
  caf::optional<network_info> find(const caf::actor& x);

  /// Maps `x` to `y` and vice versa.
  void add(const caf::actor& x, const network_info& y);

  /// Removes mapping for `x` and the corresponding network_info.
  void remove(const caf::actor& x);

  /// Removes mapping for `x` and the corresponding actor handle.
  void remove(const network_info& x);

  /// @cond PRIVATE

  void mm(caf::actor hdl) {
    mm_ = hdl;
  }

  /// @endcond

private:
  /// Points to the parent.
  caf::event_based_actor* self;

  /// Type-erased reference to the I/O or OpenSSL middleman actor.
  caf::actor mm_;

  /// Maps remote actor handles to network addresses.
  std::unordered_map<caf::actor, network_info> addrs_;

  /// Maps network addresses to remote actor handles.
  std::unordered_map<network_info, caf::actor> hdls_;
};

} // namespace broker::detail

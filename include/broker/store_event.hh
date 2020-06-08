#pragma once

#include <cstdint>
#include <string>

#include "broker/convert.hh"
#include "broker/data.hh"
#include "broker/publisher_id.hh"

namespace broker {

/// Wraps view types for convenient handling of store events.
class store_event {
public:
  enum class type : uint8_t {
    insert,
    update,
    erase,
  };

  /// A view into a ::data object representing an `insert` event.
  /// Broker encodes `insert` events as:
  ///
  /// ```
  /// [
  ///   "insert",
  ///   store_id: string,
  ///   key: data,
  ///   value: data,
  ///   expiry: optional<timespan>,
  ///   publisher_endpoint: caf::node_id,
  ///   publisher_object: uint64_t
  /// ]
  /// ```
  ///
  /// Whereas the `publisher_endpoint` and the `publisher_object` encode a
  /// @ref publisher_id.
  class insert {
  public:
    insert(const insert&) noexcept = default;

    insert& operator=(const insert&) noexcept = default;

    static insert make(const data& src) noexcept {
      if (auto xs = get_if<vector>(src))
        return make(*xs);
      return insert{nullptr};
    }

    static insert make(const vector& xs) noexcept;

    explicit operator bool() const noexcept {
      return xs_ != nullptr;
    }

    const std::string& store_id() const noexcept {
      return get<std::string>((*xs_)[1]);
    }

    const data& key() const noexcept {
      return (*xs_)[2];
    }

    const data& value() const noexcept {
      return (*xs_)[3];
    }

    caf::optional<timespan> expiry() const noexcept {
      if (auto value = get_if<timespan>((*xs_)[4]))
        return *value;
      return nil;
    }

    publisher_id publisher() const noexcept {
      if (auto value = to<caf::node_id>((*xs_)[5])) {
        return {std::move(*value), get<uint64_t>((*xs_)[6])};
      }
      return {};
    }

  private:
    explicit insert(const vector* xs) noexcept : xs_(xs) {
      // nop
    }

    const vector* xs_;
  };

  /// A view into a ::data object representing a `update` event.
  /// Broker encodes `update` events as
  /// ```
  /// [
  ///   "update",
  ///   store_id: string,
  ///   key: data,
  ///   value: data,
  ///   expiry: optional<timespan>
  ///   publisher_endpoint: caf::node_id,
  ///   publisher_object: uint64_t
  /// ]`.
  /// ```
  class update {
  public:
    update(const update&) noexcept = default;

    update& operator=(const update&) noexcept = default;

    static update make(const data& src) noexcept {
      if (auto xs = get_if<vector>(src))
        return make(*xs);
      return update{nullptr};
    }

    static update make(const vector& xs) noexcept;

    explicit operator bool() const noexcept {
      return xs_ != nullptr;
    }

    const std::string& store_id() const noexcept {
      return get<std::string>((*xs_)[1]);
    }

    const data& key() const noexcept {
      return (*xs_)[2];
    }

    const data& old_value() const noexcept {
      return (*xs_)[3];
    }

    const data& new_value() const noexcept {
      return (*xs_)[4];
    }

    caf::optional<timespan> expiry() const noexcept {
      if (auto value = get_if<timespan>((*xs_)[5]))
        return *value;
      return nil;
    }

    publisher_id publisher() const noexcept {
      if (auto value = to<caf::node_id>((*xs_)[6])) {
        return {*value, get<uint64_t>((*xs_)[7])};
      }
      return {};
    }

  private:
    explicit update(const vector* xs) noexcept : xs_(xs) {
      // nop
    }

    const vector* xs_;
  };

  /// A view into a ::data object representing an `erase` event.
  /// Broker encodes `erase` events as
  /// ```
  /// [
  ///   "erase",
  ///   store_id: string,
  ///   key: data,
  ///   publisher_endpoint: caf::node_id,
  ///   publisher_object: uint64_t
  /// ]
  /// ```
  class erase {
  public:
    erase(const erase&) noexcept = default;

    erase& operator=(const erase&) noexcept = default;

    static erase make(const data& src) noexcept {
      if (auto xs = get_if<vector>(src))
        return make(*xs);
      return erase{nullptr};
    }

    static erase make(const vector& xs) noexcept;

    explicit operator bool() const noexcept {
      return xs_ != nullptr;
    }

    const std::string& store_id() const noexcept {
      return get<std::string>((*xs_)[1]);
    }

    const data& key() const noexcept {
      return (*xs_)[2];
    }

    publisher_id publisher() const noexcept {
      if (auto value = to<caf::node_id>((*xs_)[3])) {
        return {*value, get<uint64_t>((*xs_)[4])};
      }
      return {};
    }

  private:
    explicit erase(const vector* xs) noexcept : xs_(xs) {
      // nop
    }

    const vector* xs_;
  };
};

/// @relates store_event::type
const char* to_string(store_event::type code) noexcept;

/// @relates store_event::insert
std::string to_string(const store_event::insert& x);

/// @relates store_event::update
std::string to_string(const store_event::update& x);

/// @relates store_event::erase
std::string to_string(const store_event::erase& x);

/// @relates store_event::type
bool convert(const std::string& src, store_event::type& dst) noexcept;

/// @relates store_event::type
bool convert(const data& src, store_event::type& dst) noexcept;

/// @relates store_event::type
bool convertible_to_store_event_type(const data& src) noexcept;

template <>
struct can_convert_predicate<store_event::type> {
  static bool check(const data& src) noexcept {
    return convertible_to_store_event_type(src);
  }
};

} // namespace broker
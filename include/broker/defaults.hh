#pragma once

#include "caf/string_view.hpp"
#include "caf/timespan.hpp"

// This header contains hard-coded default values for various Broker options.

namespace broker::defaults {

extern const caf::string_view recording_directory;

extern const size_t output_generator_file_cap;

} // namespace broker::defaults

namespace broker::defaults::path_blacklist {

extern const caf::timespan aging_interval;

extern const caf::timespan max_age;

} // namespace broker::defaults::path_blacklist

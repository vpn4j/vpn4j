#include "vpn4j/status.hpp"

namespace vpn4j {

Status Status::ok_status() {
    return Status{Code::Ok, {}};
}

Status Status::error(Code code, std::string_view message) {
    return Status{code, std::string{message}};
}

}  // namespace vpn4j

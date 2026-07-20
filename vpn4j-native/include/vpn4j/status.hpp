#pragma once

#include <string>
#include <string_view>

namespace vpn4j {

enum class Code {
    Ok = 0,
    InvalidArgument = 1,
    IoError = 2,
    NotSupported = 3,
    Closed = 4,
};

struct Status {
    Code code{Code::Ok};
    std::string message;

    [[nodiscard]] constexpr bool ok() const noexcept { return code == Code::Ok; }

    static Status ok_status();
    static Status error(Code code, std::string_view message);
};

}  // namespace vpn4j

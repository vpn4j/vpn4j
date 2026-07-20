#pragma once

#include "vpn4j/status.hpp"

#include <cstdint>
#include <string>

namespace vpn4j {

/**
 * Opaque TUN handle owned by C++. Java only sees a long.
 * Open/read/write may be stubs until platform TUN is wired.
 */
class TunDevice {
public:
    explicit TunDevice(std::string interface_name);
    ~TunDevice();

    TunDevice(const TunDevice&) = delete;
    TunDevice& operator=(const TunDevice&) = delete;
    TunDevice(TunDevice&&) noexcept;
    TunDevice& operator=(TunDevice&&) noexcept;

    [[nodiscard]] const std::string& interface_name() const noexcept { return interface_name_; }
    [[nodiscard]] bool open() const noexcept { return fd_ >= 0; }
    [[nodiscard]] int fd() const noexcept { return fd_; }

    Status open_device();
    void close_device() noexcept;

    /** Copy into caller buffer from native staging / TUN. */
    Status read(std::uint8_t* dst, int offset, int length, int& out_n);
    Status write(const std::uint8_t* src, int offset, int length, int& out_n);

private:
    std::string interface_name_;
    int fd_{-1};
};

}  // namespace vpn4j

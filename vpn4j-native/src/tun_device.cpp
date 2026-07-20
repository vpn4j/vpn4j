#include "vpn4j/tun_device.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <utility>

namespace vpn4j {
namespace {

Status errno_status(Code code, const char* prefix) {
    const char* err = std::strerror(errno);
    std::string msg{prefix};
    msg += ": ";
    msg += err != nullptr ? err : "unknown";
    return Status::error(code, msg);
}

}  // namespace

TunDevice::TunDevice(std::string interface_name) : interface_name_(std::move(interface_name)) {}

TunDevice::~TunDevice() {
    close_device();
}

TunDevice::TunDevice(TunDevice&& other) noexcept
    : interface_name_(std::move(other.interface_name_)), fd_(other.fd_) {
    other.fd_ = -1;
}

TunDevice& TunDevice::operator=(TunDevice&& other) noexcept {
    if (this != &other) {
        close_device();
        interface_name_ = std::move(other.interface_name_);
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

Status TunDevice::open_device() {
    if (interface_name_.empty()) {
        return Status::error(Code::InvalidArgument, "interface name empty");
    }
    if (interface_name_.size() >= IFNAMSIZ) {
        return Status::error(Code::InvalidArgument, "interface name too long");
    }
    if (fd_ >= 0) {
        return Status::ok_status();
    }

    const int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return errno_status(Code::IoError, "open /dev/net/tun");
    }

    ifreq ifr{};
    ifr.ifr_flags = static_cast<short>(IFF_TUN | IFF_NO_PI);
    std::strncpy(ifr.ifr_name, interface_name_.c_str(), IFNAMSIZ - 1);

    if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
        const Status st = errno_status(Code::IoError, "TUNSETIFF");
        ::close(fd);
        return st;
    }

    interface_name_.assign(ifr.ifr_name);
    fd_ = fd;
    return Status::ok_status();
}

void TunDevice::close_device() noexcept {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

Status TunDevice::read(std::uint8_t* dst, int offset, int length, int& out_n) {
    out_n = 0;
    if (fd_ < 0) {
        return Status::error(Code::Closed, "tun closed");
    }
    if (dst == nullptr || offset < 0 || length < 0) {
        return Status::error(Code::InvalidArgument, "bad read args");
    }
    const ssize_t n = ::read(fd_, dst + offset, static_cast<std::size_t>(length));
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            out_n = 0;
            return Status::ok_status();
        }
        return errno_status(Code::IoError, "tun read");
    }
    out_n = static_cast<int>(n);
    return Status::ok_status();
}

Status TunDevice::write(const std::uint8_t* src, int offset, int length, int& out_n) {
    out_n = 0;
    if (fd_ < 0) {
        return Status::error(Code::Closed, "tun closed");
    }
    if (src == nullptr || offset < 0 || length < 0) {
        return Status::error(Code::InvalidArgument, "bad write args");
    }
    const ssize_t n = ::write(fd_, src + offset, static_cast<std::size_t>(length));
    if (n < 0) {
        return errno_status(Code::IoError, "tun write");
    }
    out_n = static_cast<int>(n);
    return Status::ok_status();
}

}  // namespace vpn4j

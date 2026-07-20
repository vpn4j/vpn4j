#include "vpn4j/status.hpp"
#include "vpn4j/tun_device.hpp"

#include <gtest/gtest.h>

TEST(StatusTest, Ok) {
    vpn4j::Status st = vpn4j::Status::ok_status();
    EXPECT_TRUE(st.ok());
    EXPECT_EQ(st.code, vpn4j::Code::Ok);
}

TEST(StatusTest, Error) {
    vpn4j::Status st = vpn4j::Status::error(vpn4j::Code::IoError, "boom");
    EXPECT_FALSE(st.ok());
    EXPECT_EQ(st.message, "boom");
}

TEST(TunDeviceTest, RejectsEmptyName) {
    vpn4j::TunDevice device{""};
    vpn4j::Status st = device.open_device();
    EXPECT_FALSE(st.ok());
    EXPECT_EQ(st.code, vpn4j::Code::InvalidArgument);
}

TEST(TunDeviceTest, OpenCloseWhenPermitted) {
    vpn4j::TunDevice device{"vpn4jtest0"};
    vpn4j::Status st = device.open_device();
    if (!st.ok()) {
        GTEST_SKIP() << "TUN open unavailable (need CAP_NET_ADMIN /dev/net/tun): " << st.message;
    }
    EXPECT_TRUE(device.open());
    EXPECT_GE(device.fd(), 0);
    device.close_device();
    EXPECT_FALSE(device.open());
}

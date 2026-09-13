//! SOCKS5 与 HTTP 正向代理共用的动态出口地址安全策略。
//!
//! 动态代理目标来自不受信任的公网请求，不能沿用固定隧道“管理员已经明确配置
//! 目标”的信任模型。默认只允许公网单播地址；显式开启私网访问后也只放行
//! RFC1918、共享地址空间与 IPv6 ULA，云元数据、回环、链路本地、组播、文档和
//! 其他保留地址始终拒绝。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// 动态出口地址的安全分类。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressAddressClass {
    Public,
    PrivateNetwork,
    CloudMetadata,
    Sensitive,
}

/// 供所有动态代理协议共用的最小化安全开关。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EgressPolicy {
    allow_private_networks: bool,
}

impl EgressPolicy {
    pub const fn public_only() -> Self {
        Self {
            allow_private_networks: false,
        }
    }

    pub const fn new(allow_private_networks: bool) -> Self {
        Self {
            allow_private_networks,
        }
    }

    pub const fn allows_private_networks(self) -> bool {
        self.allow_private_networks
    }

    /// 校验实际准备连接或发送数据报的 IP。错误文本只包含稳定机器码，不包含目标。
    pub fn validate_ip(self, address: IpAddr) -> Result<(), EgressPolicyError> {
        match classify_ip(address) {
            EgressAddressClass::Public => Ok(()),
            EgressAddressClass::PrivateNetwork if self.allow_private_networks => Ok(()),
            EgressAddressClass::PrivateNetwork => Err(EgressPolicyError::PrivateNetworkDenied),
            EgressAddressClass::CloudMetadata => Err(EgressPolicyError::CloudMetadataDenied),
            EgressAddressClass::Sensitive => Err(EgressPolicyError::SensitiveAddressDenied),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum EgressPolicyError {
    #[error("private_network_target_denied")]
    PrivateNetworkDenied,
    #[error("cloud_metadata_target_denied")]
    CloudMetadataDenied,
    #[error("sensitive_network_target_denied")]
    SensitiveAddressDenied,
}

impl EgressPolicyError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::PrivateNetworkDenied => "private_network_target_denied",
            Self::CloudMetadataDenied => "cloud_metadata_target_denied",
            Self::SensitiveAddressDenied => "sensitive_network_target_denied",
        }
    }
}

pub fn classify_ip(address: IpAddr) -> EgressAddressClass {
    match address {
        IpAddr::V4(address) => classify_ipv4(address),
        IpAddr::V6(address) => classify_ipv6(address),
    }
}

fn classify_ipv4(address: Ipv4Addr) -> EgressAddressClass {
    // 这些地址由云平台基础设施使用，即使位于可选放行的共享地址空间也必须拒绝。
    if matches!(
        address.octets(),
        [169, 254, 169, 254] | [100, 100, 100, 200] | [168, 63, 129, 16]
    ) {
        return EgressAddressClass::CloudMetadata;
    }

    if ipv4_in_prefix(address, Ipv4Addr::new(10, 0, 0, 0), 8)
        || ipv4_in_prefix(address, Ipv4Addr::new(100, 64, 0, 0), 10)
        || ipv4_in_prefix(address, Ipv4Addr::new(172, 16, 0, 0), 12)
        || ipv4_in_prefix(address, Ipv4Addr::new(192, 168, 0, 0), 16)
    {
        return EgressAddressClass::PrivateNetwork;
    }

    if ipv4_in_prefix(address, Ipv4Addr::UNSPECIFIED, 8)
        || ipv4_in_prefix(address, Ipv4Addr::LOCALHOST, 8)
        || ipv4_in_prefix(address, Ipv4Addr::new(169, 254, 0, 0), 16)
        || ipv4_in_prefix(address, Ipv4Addr::new(192, 0, 0, 0), 24)
        || ipv4_in_prefix(address, Ipv4Addr::new(192, 0, 2, 0), 24)
        || ipv4_in_prefix(address, Ipv4Addr::new(192, 88, 99, 0), 24)
        || ipv4_in_prefix(address, Ipv4Addr::new(198, 18, 0, 0), 15)
        || ipv4_in_prefix(address, Ipv4Addr::new(198, 51, 100, 0), 24)
        || ipv4_in_prefix(address, Ipv4Addr::new(203, 0, 113, 0), 24)
        || ipv4_in_prefix(address, Ipv4Addr::new(224, 0, 0, 0), 4)
        || ipv4_in_prefix(address, Ipv4Addr::new(240, 0, 0, 0), 4)
    {
        return EgressAddressClass::Sensitive;
    }

    EgressAddressClass::Public
}

fn classify_ipv6(address: Ipv6Addr) -> EgressAddressClass {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return classify_ipv4(mapped);
    }

    // RFC 6052 的公用 NAT64 前缀携带实际 IPv4 目标，必须校验嵌入地址，防止用
    // IPv6 表示绕过 IPv4 私网和元数据地址限制。
    if ipv6_in_prefix(address, Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96) {
        let octets = address.octets();
        return classify_ipv4(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }

    if address == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254) {
        return EgressAddressClass::CloudMetadata;
    }

    if ipv6_in_prefix(address, Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7) {
        return EgressAddressClass::PrivateNetwork;
    }

    if address.is_unspecified()
        || address.is_loopback()
        || ipv6_in_prefix(address, Ipv6Addr::UNSPECIFIED, 96)
        || ipv6_in_prefix(
            address,
            Ipv6Addr::new(0x0064, 0xff9b, 0x0001, 0, 0, 0, 0, 0),
            48,
        )
        || ipv6_in_prefix(address, Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64)
        || ipv6_in_prefix(address, Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23)
        || ipv6_in_prefix(address, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
        || ipv6_in_prefix(address, Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16)
        || ipv6_in_prefix(address, Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20)
        || ipv6_in_prefix(address, Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16)
        || ipv6_in_prefix(address, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10)
        || ipv6_in_prefix(address, Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10)
        || ipv6_in_prefix(address, Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8)
        || !ipv6_in_prefix(address, Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3)
    {
        return EgressAddressClass::Sensitive;
    }

    EgressAddressClass::Public
}

fn ipv4_in_prefix(address: Ipv4Addr, network: Ipv4Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(address) & mask) == (u32::from(network) & mask)
}

fn ipv6_in_prefix(address: Ipv6Addr, network: Ipv6Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(address) & mask) == (u128::from(network) & mask)
}

#[cfg(test)]
mod tests {
    use super::{classify_ip, EgressAddressClass, EgressPolicy, EgressPolicyError};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn public_addresses_are_allowed_by_default() {
        let policy = EgressPolicy::public_only();
        for address in [
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            "2606:4700:4700::1111".parse().unwrap(),
            "64:ff9b::0808:0808".parse().unwrap(),
        ] {
            assert_eq!(classify_ip(address), EgressAddressClass::Public);
            assert_eq!(policy.validate_ip(address), Ok(()));
        }
    }

    #[test]
    fn private_networks_require_the_explicit_override() {
        let default = EgressPolicy::public_only();
        let private = EgressPolicy::new(true);
        for address in [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(172, 31, 255, 254)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            "fd12:3456:789a::1".parse().unwrap(),
            "::ffff:192.168.1.1".parse().unwrap(),
        ] {
            assert_eq!(classify_ip(address), EgressAddressClass::PrivateNetwork);
            assert_eq!(
                default.validate_ip(address),
                Err(EgressPolicyError::PrivateNetworkDenied)
            );
            assert_eq!(private.validate_ip(address), Ok(()));
        }
    }

    #[test]
    fn cloud_metadata_is_never_unlocked_by_private_access() {
        let private = EgressPolicy::new(true);
        for address in [
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200)),
            IpAddr::V4(Ipv4Addr::new(168, 63, 129, 16)),
            "fd00:ec2::254".parse().unwrap(),
            "::ffff:169.254.169.254".parse().unwrap(),
            "64:ff9b::a9fe:a9fe".parse().unwrap(),
        ] {
            assert_eq!(classify_ip(address), EgressAddressClass::CloudMetadata);
            assert_eq!(
                private.validate_ip(address),
                Err(EgressPolicyError::CloudMetadataDenied)
            );
        }
    }

    #[test]
    fn loopback_link_local_and_reserved_addresses_always_fail_closed() {
        let private = EgressPolicy::new(true);
        for address in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            "fe80::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            "ff02::1".parse().unwrap(),
        ] {
            assert_eq!(classify_ip(address), EgressAddressClass::Sensitive);
            assert_eq!(
                private.validate_ip(address),
                Err(EgressPolicyError::SensitiveAddressDenied)
            );
        }
    }
}

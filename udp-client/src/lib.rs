#![cfg_attr(
    not(feature = "agave-unstable-api"),
    deprecated(
        since = "3.1.0",
        note = "This crate has been marked for formal inclusion in the Agave Unstable API. From \
                v4.0.0 onward, the `agave-unstable-api` crate feature must be specified to \
                acknowledge use of an interface that may break without warning."
    )
)]
#![allow(clippy::arithmetic_side_effects)]

pub mod nonblocking;
pub mod udp_client;

use {
    crate::{
        nonblocking::udp_client::UdpClientConnection as NonblockingUdpConnection,
        udp_client::UdpClientConnection as BlockingUdpConnection,
    },
    solana_connection_cache::{
        connection_cache::{
            BaseClientConnection, ClientError, ConnectionManager, ConnectionPool,
            ConnectionPoolError, NewConnectionConfig, Protocol,
        },
        connection_cache_stats::ConnectionCacheStats,
    },
    solana_keypair::Keypair,
    solana_net_utils::sockets::{self, SocketConfiguration},
    std::{
        net::{SocketAddr, UdpSocket},
        sync::Arc,
    },
};

pub struct UdpPool {
    connections: Vec<Arc<Udp>>,
}
impl ConnectionPool for UdpPool {
    type BaseClientConnection = Udp;
    type NewConnectionConfig = UdpConfig;

    fn add_connection(&mut self, config: &Self::NewConnectionConfig, addr: &SocketAddr) -> usize {
        let connection = self.create_pool_entry(config, addr);
        let idx = self.connections.len();
        self.connections.push(connection);
        idx
    }

    fn num_connections(&self) -> usize {
        self.connections.len()
    }

    fn get(&self, index: usize) -> Result<Arc<Self::BaseClientConnection>, ConnectionPoolError> {
        self.connections
            .get(index)
            .cloned()
            .ok_or(ConnectionPoolError::IndexOutOfRange)
    }

    fn create_pool_entry(
        &self,
        config: &Self::NewConnectionConfig,
        _addr: &SocketAddr,
    ) -> Arc<Self::BaseClientConnection> {
        Arc::new(Udp(config.udp_socket.clone()))
    }
}

pub struct UdpConfig {
    udp_socket: Arc<UdpSocket>,
}

impl NewConnectionConfig for UdpConfig {
    fn new() -> Result<Self, ClientError> {
        // Use UNSPECIFIED for production validators to bind to all interfaces
        // Use LOCALHOST only in dev/test context to avoid port conflicts in CI
        #[cfg(not(feature = "dev-context-only-utils"))]
        let bind_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
        #[cfg(feature = "dev-context-only-utils")]
        let bind_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        // This will bind to random ports, but VALIDATOR_PORT_RANGE is outside
        // of the range for CI tests when this is running in CI
        let socket = sockets::bind_in_range_with_config(
            bind_ip,
            solana_net_utils::VALIDATOR_PORT_RANGE,
            SocketConfiguration::default(),
        )
        .map_err(Into::<ClientError>::into)?;
        Ok(Self {
            udp_socket: Arc::new(socket.1),
        })
    }
}

pub struct Udp(Arc<UdpSocket>);
impl BaseClientConnection for Udp {
    type BlockingClientConnection = BlockingUdpConnection;
    type NonblockingClientConnection = NonblockingUdpConnection;

    fn new_blocking_connection(
        &self,
        addr: SocketAddr,
        _stats: Arc<ConnectionCacheStats>,
    ) -> Arc<Self::BlockingClientConnection> {
        Arc::new(BlockingUdpConnection::new_from_addr(self.0.clone(), addr))
    }

    fn new_nonblocking_connection(
        &self,
        addr: SocketAddr,
        _stats: Arc<ConnectionCacheStats>,
    ) -> Arc<Self::NonblockingClientConnection> {
        Arc::new(NonblockingUdpConnection::new_from_addr(
            self.0.try_clone().unwrap(),
            addr,
        ))
    }
}

#[derive(Default)]
pub struct UdpConnectionManager {}

impl ConnectionManager for UdpConnectionManager {
    type ConnectionPool = UdpPool;
    type NewConnectionConfig = UdpConfig;

    const PROTOCOL: Protocol = Protocol::UDP;

    fn new_connection_pool(&self) -> Self::ConnectionPool {
        UdpPool {
            connections: Vec::default(),
        }
    }

    fn new_connection_config(&self) -> Self::NewConnectionConfig {
        UdpConfig::new().unwrap()
    }

    fn update_key(&self, _key: &Keypair) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

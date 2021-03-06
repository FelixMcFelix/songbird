#[cfg(feature = "driver-core")]
use crate::{
    driver::{Config, Driver},
    error::ConnectionResult,
};
use crate::{
    error::{JoinError, JoinResult},
    id::{ChannelId, GuildId, UserId},
    info::{ConnectionInfo, ConnectionProgress},
    shards::Shard,
};
use flume::{r#async::RecvFut, Sender};
use serde_json::json;
use tracing::instrument;

#[cfg(feature = "driver-core")]
use std::ops::{Deref, DerefMut};

#[derive(Clone, Debug)]
enum Return {
    Info(Sender<ConnectionInfo>),
    #[cfg(feature = "driver-core")]
    Conn(Sender<ConnectionResult<()>>),
}

/// The Call handler is responsible for a single voice connection, acting
/// as a clean API above the inner state and gateway message management.
///
/// If the `"driver"` feature is enabled, then a Call exposes all control methods of
/// [`Driver`] via `Deref(Mut)`.
///
/// [`Driver`]: struct@Driver
#[derive(Clone, Debug)]
pub struct Call {
    connection: Option<(ChannelId, ConnectionProgress, Return)>,

    #[cfg(feature = "driver-core")]
    /// The internal controller of the voice connection monitor thread.
    driver: Driver,

    guild_id: GuildId,
    /// Whether the current handler is set to deafen voice connections.
    self_deaf: bool,
    /// Whether the current handler is set to mute voice connections.
    self_mute: bool,
    user_id: UserId,
    /// Will be set when a `Call` is made via the [`new`]
    /// method.
    ///
    /// When set via [`standalone`](`Call::standalone`), it will not be
    /// present.
    ///
    /// [`new`]: Call::new
    /// [`standalone`]: Call::standalone
    ws: Option<Shard>,
}

impl Call {
    /// Creates a new Call, which will send out WebSocket messages via
    /// the given shard.
    #[inline]
    #[instrument]
    pub fn new(guild_id: GuildId, ws: Shard, user_id: UserId) -> Self {
        Self::new_raw(guild_id, Some(ws), user_id)
    }

    #[cfg(feature = "driver-core")]
    /// Creates a new Call, configuring the driver as specified.
    #[inline]
    #[instrument]
    pub fn from_driver_config(
        guild_id: GuildId,
        ws: Shard,
        user_id: UserId,
        config: Config,
    ) -> Self {
        Self::new_raw_cfg(guild_id, Some(ws), user_id, config)
    }

    /// Creates a new, standalone Call which is not connected via
    /// WebSocket to the Gateway.
    ///
    /// Actions such as muting, deafening, and switching channels will not
    /// function through this Call and must be done through some other
    /// method, as the values will only be internally updated.
    ///
    /// For most use cases you do not want this.
    #[inline]
    #[instrument]
    pub fn standalone(guild_id: GuildId, user_id: UserId) -> Self {
        Self::new_raw(guild_id, None, user_id)
    }

    #[cfg(feature = "driver-core")]
    /// Creates a new standalone Call, configuring the driver as specified.
    #[inline]
    #[instrument]
    pub fn standalone_from_driver_config(
        guild_id: GuildId,
        user_id: UserId,
        config: Config,
    ) -> Self {
        Self::new_raw_cfg(guild_id, None, user_id, config)
    }

    fn new_raw(guild_id: GuildId, ws: Option<Shard>, user_id: UserId) -> Self {
        Call {
            connection: None,
            #[cfg(feature = "driver-core")]
            driver: Default::default(),
            guild_id,
            self_deaf: false,
            self_mute: false,
            user_id,
            ws,
        }
    }

    #[cfg(feature = "driver-core")]
    fn new_raw_cfg(guild_id: GuildId, ws: Option<Shard>, user_id: UserId, config: Config) -> Self {
        Call {
            connection: None,
            driver: Driver::new(config),
            guild_id,
            self_deaf: false,
            self_mute: false,
            user_id,
            ws,
        }
    }

    #[instrument(skip(self))]
    fn do_connect(&mut self) {
        match &self.connection {
            Some((_, ConnectionProgress::Complete(c), Return::Info(tx))) => {
                // It's okay if the receiver hung up.
                let _ = tx.send(c.clone());
            },
            #[cfg(feature = "driver-core")]
            Some((_, ConnectionProgress::Complete(c), Return::Conn(tx))) => {
                self.driver.raw_connect(c.clone(), tx.clone());
            },
            _ => {},
        }
    }

    /// Sets whether the current connection is to be deafened.
    ///
    /// If there is no live voice connection, then this only acts as a settings
    /// update for future connections.
    ///
    /// **Note**: Unlike in the official client, you _can_ be deafened while
    /// not being muted.
    ///
    /// **Note**: If the `Call` was created via [`standalone`], then this
    /// will _only_ update whether the connection is internally deafened.
    ///
    /// [`standalone`]: Call::standalone
    #[instrument(skip(self))]
    pub async fn deafen(&mut self, deaf: bool) -> JoinResult<()> {
        self.self_deaf = deaf;

        self.update().await
    }

    /// Returns whether the current connection is self-deafened in this server.
    ///
    /// This is purely cosmetic.
    #[instrument(skip(self))]
    pub fn is_deaf(&self) -> bool {
        self.self_deaf
    }

    #[cfg(feature = "driver-core")]
    /// Connect or switch to the given voice channel by its Id.
    ///
    /// This function acts as a future in two stages:
    /// * The first `await` sends the request over the gateway.
    /// * The second `await`s a the driver's connection attempt.
    ///   To prevent deadlock, any mutexes around this Call
    ///   *must* be released before this result is queried.
    ///
    /// When using [`Songbird::join`], this pattern is correctly handled for you.
    ///
    /// [`Songbird::join`]: crate::Songbird::join
    #[instrument(skip(self))]
    pub async fn join(
        &mut self,
        channel_id: ChannelId,
    ) -> JoinResult<RecvFut<'static, ConnectionResult<()>>> {
        let (tx, rx) = flume::unbounded();

        self.connection = Some((
            channel_id,
            ConnectionProgress::new(self.guild_id, self.user_id),
            Return::Conn(tx),
        ));

        self.update().await.map(|_| rx.into_recv_async())
    }

    /// Join the selected voice channel, *without* running/starting an RTP
    /// session or running the driver.
    ///
    /// Use this if you require connection info for lavalink,
    /// some other voice implementation, or don't want to use the driver for a given call.
    ///
    /// This function acts as a future in two stages:
    /// * The first `await` sends the request over the gateway.
    /// * The second `await`s voice session data from Discord.
    ///   To prevent deadlock, any mutexes around this Call
    ///   *must* be released before this result is queried.
    ///
    /// When using [`Songbird::join_gateway`], this pattern is correctly handled for you.
    ///
    /// [`Songbird::join_gateway`]: crate::Songbird::join_gateway
    #[instrument(skip(self))]
    pub async fn join_gateway(
        &mut self,
        channel_id: ChannelId,
    ) -> JoinResult<RecvFut<'static, ConnectionInfo>> {
        let (tx, rx) = flume::unbounded();

        self.connection = Some((
            channel_id,
            ConnectionProgress::new(self.guild_id, self.user_id),
            Return::Info(tx),
        ));

        self.update().await.map(|_| rx.into_recv_async())
    }

    /// Returns the current voice connection details for this Call,
    /// if available.
    #[instrument(skip(self))]
    pub fn current_connection(&self) -> Option<&ConnectionInfo> {
        match &self.connection {
            Some((_, progress, _)) => progress.get_connection_info(),
            _ => None,
        }
    }

    /// Returns `id` of the channel, if connected to any.
    ///
    /// **Note:**: Returned `id` is of the channel, to which bot performed connection.
    /// It is possible that it is different from actual channel due to ability of server's admin to
    /// move bot from channel to channel. This is to be fixed with next breaking change release.
    #[instrument(skip(self))]
    pub fn current_channel(&self) -> Option<ChannelId> {
        match &self.connection {
            Some((id, _, _)) => Some(*id),
            _ => None,
        }
    }

    /// Leaves the current voice channel, disconnecting from it.
    ///
    /// This does _not_ forget settings, like whether to be self-deafened or
    /// self-muted.
    ///
    /// **Note**: If the `Call` was created via [`standalone`], then this
    /// will _only_ update whether the connection is internally connected to a
    /// voice channel.
    ///
    /// [`standalone`]: Call::standalone
    #[instrument(skip(self))]
    pub async fn leave(&mut self) -> JoinResult<()> {
        // Only send an update if we were in a voice channel.
        self.connection = None;

        #[cfg(feature = "driver-core")]
        self.driver.leave();

        self.update().await
    }

    /// Sets whether the current connection is to be muted.
    ///
    /// If there is no live voice connection, then this only acts as a settings
    /// update for future connections.
    ///
    /// **Note**: If the `Call` was created via [`standalone`], then this
    /// will _only_ update whether the connection is internally muted.
    ///
    /// [`standalone`]: Call::standalone
    #[instrument(skip(self))]
    pub async fn mute(&mut self, mute: bool) -> JoinResult<()> {
        self.self_mute = mute;

        #[cfg(feature = "driver-core")]
        self.driver.mute(mute);

        self.update().await
    }

    /// Returns whether the current connection is self-muted in this server.
    #[instrument(skip(self))]
    pub fn is_mute(&self) -> bool {
        self.self_mute
    }

    /// Updates the voice server data.
    ///
    /// You should only need to use this if you initialized the `Call` via
    /// [`standalone`].
    ///
    /// [`standalone`]: Call::standalone
    #[instrument(skip(self, token))]
    pub fn update_server(&mut self, endpoint: String, token: String) {
        let try_conn = if let Some((_, ref mut progress, _)) = self.connection.as_mut() {
            progress.apply_server_update(endpoint, token)
        } else {
            false
        };

        if try_conn {
            self.do_connect();
        }
    }

    /// Updates the internal voice state of the current user.
    ///
    /// You should only need to use this if you initialized the `Call` via
    /// [`standalone`].
    ///
    /// [`standalone`]: Call::standalone
    #[instrument(skip(self))]
    pub fn update_state(&mut self, session_id: String) {
        let try_conn = if let Some((_, ref mut progress, _)) = self.connection.as_mut() {
            progress.apply_state_update(session_id)
        } else {
            false
        };

        if try_conn {
            self.do_connect();
        }
    }

    /// Send an update for the current session over WS.
    ///
    /// Does nothing if initialized via [`standalone`].
    ///
    /// [`standalone`]: Call::standalone
    #[instrument(skip(self))]
    async fn update(&mut self) -> JoinResult<()> {
        if let Some(ws) = self.ws.as_mut() {
            let map = json!({
                "op": 4,
                "d": {
                    "channel_id": self.connection.as_ref().map(|c| c.0.0),
                    "guild_id": self.guild_id.0,
                    "self_deaf": self.self_deaf,
                    "self_mute": self.self_mute,
                }
            });

            ws.send(map).await
        } else {
            Err(JoinError::NoSender)
        }
    }
}

#[cfg(feature = "driver-core")]
impl Deref for Call {
    type Target = Driver;

    fn deref(&self) -> &Self::Target {
        &self.driver
    }
}

#[cfg(feature = "driver-core")]
impl DerefMut for Call {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.driver
    }
}

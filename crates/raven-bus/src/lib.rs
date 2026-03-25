//! raven-bus — lightweight async event bus.
//!
//! Wraps `tokio::sync::broadcast` so all framework components can
//! publish and subscribe to `BusEvent` without direct coupling.

use raven_core::{BusEvent, OsintError};
use tokio::sync::broadcast;
use tracing::{debug, warn};

/// Default channel capacity (number of events buffered before lagging).
const DEFAULT_CAPACITY: usize = 256;

// ─────────────────────────────────────────────────────────────────────────────
// RavenBus
// ─────────────────────────────────────────────────────────────────────────────

/// Central event bus.  Clone to get additional handles (cheap — just clones the
/// inner `Sender`).
#[derive(Clone, Debug)]
pub struct RavenBus {
    tx: broadcast::Sender<BusEvent>,
}

impl RavenBus {
    /// Create a new bus with the default buffer capacity.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(DEFAULT_CAPACITY);
        Self { tx }
    }

    /// Publish an event.  Returns an error if there are no subscribers.
    pub fn publish(&self, event: BusEvent) -> Result<usize, OsintError> {
        debug!(event_type = %event_type_name(&event), "bus: publishing event");
        self.tx
            .send(event)
            .map_err(|e| OsintError::Bus(e.to_string()))
    }

    /// Subscribe and receive a fresh receiver.
    /// Events published *before* this call are not delivered (broadcast semantics).
    pub fn subscribe(&self) -> BusReceiver {
        BusReceiver {
            rx: self.tx.subscribe(),
        }
    }
}

impl Default for RavenBus {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BusReceiver
// ─────────────────────────────────────────────────────────────────────────────

/// A handle for receiving events from the bus.
pub struct BusReceiver {
    rx: broadcast::Receiver<BusEvent>,
}

impl BusReceiver {
    /// Wait for the next event.
    /// Returns `None` if the bus has been dropped (all senders gone).
    /// Returns an error if the receiver lagged (missed events due to slow
    /// consumption — increase `DEFAULT_CAPACITY` or consume faster).
    pub async fn recv(&mut self) -> Option<Result<BusEvent, OsintError>> {
        match self.rx.recv().await {
            Ok(event) => Some(Ok(event)),
            Err(broadcast::error::RecvError::Closed) => None,
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(skipped = n, "bus: receiver lagged, events dropped");
                Some(Err(OsintError::Bus(format!(
                    "receiver lagged, {n} events dropped"
                ))))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn event_type_name(e: &BusEvent) -> &'static str {
    match e {
        BusEvent::TargetQueued(_) => "TargetQueued",
        BusEvent::DiscoveryQueued(_) => "DiscoveryQueued",
        BusEvent::DiscoveryUrlsFound { .. } => "DiscoveryUrlsFound",
        BusEvent::DiscoveryComplete(_) => "DiscoveryComplete",
        BusEvent::DiscoveryFailed { .. } => "DiscoveryFailed",
        BusEvent::ScrapeDone(_) => "ScrapeDone",
        BusEvent::AgentDone { .. } => "AgentDone",
        BusEvent::LlmVerified { .. } => "LlmVerified",
        BusEvent::PipelineComplete { .. } => "PipelineComplete",
        BusEvent::PipelineFailed { .. } => "PipelineFailed",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::OsintTarget;

    #[tokio::test]
    async fn publish_and_receive() {
        let bus = RavenBus::new();
        let mut rx = bus.subscribe();

        let target = OsintTarget::new("https://example.com");
        let id = target.id;

        bus.publish(BusEvent::TargetQueued(target))
            .expect("publish failed");

        let event = rx.recv().await.expect("no event").expect("recv error");
        match event {
            BusEvent::TargetQueued(t) => assert_eq!(t.id, id),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn bus_returns_none_when_dropped() {
        let bus = RavenBus::new();
        let mut rx = bus.subscribe();
        drop(bus);
        assert!(rx.recv().await.is_none());
    }
}

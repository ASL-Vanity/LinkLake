use serde::Serialize;
use std::{fmt, sync::Mutex, time::Duration};

/// 服务端对外暴露的生命周期阶段。
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LifecyclePhase {
    Starting,
    Ready,
    Draining,
    Stopping,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct LifecycleSnapshot {
    pub(crate) phase: LifecyclePhase,
    pub(crate) startup_complete: bool,
    pub(crate) phase_changed_unix_seconds: u64,
    pub(crate) drain_deadline_unix_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct LifecycleState {
    phase: LifecyclePhase,
    startup_complete: bool,
    phase_changed_unix_seconds: u64,
    drain_deadline_unix_seconds: Option<u64>,
}

pub(crate) struct LifecycleController {
    state: Mutex<LifecycleState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LifecycleTransitionError {
    StartupIncomplete,
    Stopping,
}

impl fmt::Display for LifecycleTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartupIncomplete => formatter.write_str("server startup is not complete"),
            Self::Stopping => formatter.write_str("server is stopping"),
        }
    }
}

impl std::error::Error for LifecycleTransitionError {}

impl LifecycleController {
    pub(crate) fn new(now_unix_seconds: u64) -> Self {
        Self {
            state: Mutex::new(LifecycleState {
                phase: LifecyclePhase::Starting,
                startup_complete: false,
                phase_changed_unix_seconds: now_unix_seconds,
                drain_deadline_unix_seconds: None,
            }),
        }
    }

    /// 只有数据库、证书恢复和所有静态监听器都成功绑定后才能调用。
    pub(crate) fn mark_ready(&self, now_unix_seconds: u64) {
        let mut state = self.state.lock().expect("lifecycle state lock poisoned");
        if state.phase != LifecyclePhase::Starting {
            return;
        }
        state.phase = LifecyclePhase::Ready;
        state.startup_complete = true;
        state.phase_changed_unix_seconds = now_unix_seconds;
        state.drain_deadline_unix_seconds = None;
    }

    pub(crate) fn begin_drain(
        &self,
        now_unix_seconds: u64,
        timeout: Duration,
    ) -> Result<LifecycleSnapshot, LifecycleTransitionError> {
        let mut state = self.state.lock().expect("lifecycle state lock poisoned");
        match state.phase {
            LifecyclePhase::Starting => return Err(LifecycleTransitionError::StartupIncomplete),
            LifecyclePhase::Stopping => return Err(LifecycleTransitionError::Stopping),
            LifecyclePhase::Ready | LifecyclePhase::Draining => {}
        }
        state.phase = LifecyclePhase::Draining;
        state.phase_changed_unix_seconds = now_unix_seconds;
        state.drain_deadline_unix_seconds =
            Some(now_unix_seconds.saturating_add(timeout.as_secs()));
        Ok(snapshot_of(*state))
    }

    pub(crate) fn resume(
        &self,
        now_unix_seconds: u64,
    ) -> Result<LifecycleSnapshot, LifecycleTransitionError> {
        let mut state = self.state.lock().expect("lifecycle state lock poisoned");
        match state.phase {
            LifecyclePhase::Starting => return Err(LifecycleTransitionError::StartupIncomplete),
            LifecyclePhase::Stopping => return Err(LifecycleTransitionError::Stopping),
            LifecyclePhase::Ready => return Ok(snapshot_of(*state)),
            LifecyclePhase::Draining => {}
        }
        state.phase = LifecyclePhase::Ready;
        state.phase_changed_unix_seconds = now_unix_seconds;
        state.drain_deadline_unix_seconds = None;
        Ok(snapshot_of(*state))
    }

    pub(crate) fn begin_stopping(&self, now_unix_seconds: u64) {
        let mut state = self.state.lock().expect("lifecycle state lock poisoned");
        state.phase = LifecyclePhase::Stopping;
        state.phase_changed_unix_seconds = now_unix_seconds;
        state.drain_deadline_unix_seconds = None;
    }

    pub(crate) fn snapshot(&self) -> LifecycleSnapshot {
        snapshot_of(*self.state.lock().expect("lifecycle state lock poisoned"))
    }

    pub(crate) fn accepts_new_work(&self) -> bool {
        self.state
            .lock()
            .expect("lifecycle state lock poisoned")
            .phase
            == LifecyclePhase::Ready
    }

    pub(crate) fn is_live(&self) -> bool {
        self.state
            .lock()
            .expect("lifecycle state lock poisoned")
            .phase
            != LifecyclePhase::Stopping
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.accepts_new_work()
    }

    pub(crate) fn startup_complete(&self) -> bool {
        self.state
            .lock()
            .expect("lifecycle state lock poisoned")
            .startup_complete
    }
}

fn snapshot_of(state: LifecycleState) -> LifecycleSnapshot {
    LifecycleSnapshot {
        phase: state.phase,
        startup_complete: state.startup_complete,
        phase_changed_unix_seconds: state.phase_changed_unix_seconds,
        drain_deadline_unix_seconds: state.drain_deadline_unix_seconds,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_transitions_are_explicit_and_reversible_before_stopping() {
        let lifecycle = LifecycleController::new(10);
        assert_eq!(lifecycle.snapshot().phase, LifecyclePhase::Starting);
        assert!(!lifecycle.accepts_new_work());
        assert_eq!(
            lifecycle.begin_drain(11, Duration::from_secs(30)),
            Err(LifecycleTransitionError::StartupIncomplete)
        );

        lifecycle.mark_ready(12);
        assert!(lifecycle.is_ready());
        assert!(lifecycle.startup_complete());

        let draining = lifecycle
            .begin_drain(20, Duration::from_secs(45))
            .expect("ready server should enter draining");
        assert_eq!(draining.phase, LifecyclePhase::Draining);
        assert_eq!(draining.drain_deadline_unix_seconds, Some(65));
        assert!(!lifecycle.accepts_new_work());
        assert!(lifecycle.is_live());

        let ready = lifecycle.resume(30).expect("draining server should resume");
        assert_eq!(ready.phase, LifecyclePhase::Ready);
        assert_eq!(ready.drain_deadline_unix_seconds, None);
    }

    #[test]
    fn stopping_is_terminal_for_management_transitions() {
        let lifecycle = LifecycleController::new(1);
        lifecycle.mark_ready(2);
        lifecycle.begin_stopping(3);
        assert!(!lifecycle.is_live());
        assert!(!lifecycle.is_ready());
        assert!(lifecycle.startup_complete());
        assert_eq!(lifecycle.resume(4), Err(LifecycleTransitionError::Stopping));
        assert_eq!(
            lifecycle.begin_drain(4, Duration::from_secs(1)),
            Err(LifecycleTransitionError::Stopping)
        );
    }
}

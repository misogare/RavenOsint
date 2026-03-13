use crate::pipeline::WorkflowRuntime;
use raven_storage::ResultStore;
use std::sync::Arc;

pub struct AppState {
    pub store: Arc<dyn ResultStore>,
    pub workflow: Arc<WorkflowRuntime>,
}

impl AppState {
    pub fn new(store: Arc<dyn ResultStore>, workflow: Arc<WorkflowRuntime>) -> Self {
        Self { store, workflow }
    }
}

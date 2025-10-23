use crate::fuzzer::xencov::XenCov;
use std::borrow::Cow;

use libafl::observers::Observer;
use libafl::Error;
use libafl_bolts::Named;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XenCovObserver {
    pub xencov: Option<XenCov>,
    name: Cow<'static, str>,
}

impl XenCovObserver {
    pub fn new(name: &'static str) -> XenCovObserver {
        XenCovObserver {
            xencov: None,
            name: Cow::from(name),
        }
    }
}

impl<I, S> Observer<I, S> for XenCovObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &libafl::executors::ExitKind,
    ) -> Result<(), libafl::Error> {
	self.xencov = XenCov::parse_from_mem();
        Ok(())
    }
}

impl Named for XenCovObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl AsRef<Self> for XenCovObserver {
    fn as_ref(&self) -> &Self {
	self
    }
}

// impl CanTrack for XenCovObserver {
//     type WithIndexTracking = XenCovObserver;
//     type WithNoveltiesTracking = XenCovObserver;
//     const INDICES: bool = true;
//     const NOVELTIES: bool = false;

//     fn track_indices(self) -> Self::WithIndexTracking {
// 	self
//     }

//     fn track_novelties(self) -> Self::WithNoveltiesTracking {
// 	self
//     }
// }

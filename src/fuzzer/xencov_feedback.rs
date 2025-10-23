use crate::fuzzer::xencov::XenCov;
use crate::fuzzer::xencov::XenCovStat;
use crate::fuzzer::xencov_observer::XenCovObserver;

use core::marker::PhantomData;
use libafl::events::{Event, EventFirer, EventWithStats};
use libafl::feedbacks::Feedback;
use libafl::feedbacks::StateInitializer;
use libafl::monitors::stats::{AggregatorOps, UserStats, UserStatsValue};
use libafl::state::HasExecutions;
use libafl::{Error, HasNamedMetadata};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use libafl_bolts::{
    tuples::{Handle, Handled, MatchName, MatchNameRef},
    Named,
};

#[derive(Clone, Debug)]
pub struct XenCovFeedback {
    /// Accumulated coverage data
    pub xencov: Option<XenCov>,
    /// Name identifier of this instance
    name: Cow<'static, str>,
    /// Name identifier of the observer
    map_ref: Handle<XenCovObserver>,
    /// Name of the feedback as shown in the `UserStats`
    stats_name: Cow<'static, str>,
}

/// The state of [`MapFeedback`]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[expect(clippy::unsafe_derive_deserialize)] // for SerdeAny
pub struct XenCovFeedbackMetadata {
    /// Accumulated coverage data
    pub xencov: Option<XenCov>,
}

libafl_bolts::impl_serdeany!(XenCovFeedbackMetadata);

impl<S> StateInitializer<S> for XenCovFeedback
where
    S: HasNamedMetadata,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        state.add_named_metadata_checked(&self.name, XenCovFeedbackMetadata::default())?;
        Ok(())
    }
}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for XenCovFeedback
where
    EM: EventFirer<I, S>,
    OT: MatchName,
    S: HasNamedMetadata + HasExecutions,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &libafl::executors::ExitKind,
    ) -> Result<bool, libafl::Error> {
//	println!("Is interesting?");

	let observer: &XenCovObserver = observers.get(&self.map_ref).expect("XenCovObserver not found. This is likely because you entered the crash handler with the wrong executor/observer").as_ref();

	let res = match observer.xencov.as_ref() {
	    None => Ok(false),
	    Some (xencov) =>
		match self.xencov.as_ref() {
		    None => Ok(true), // First time is always interesting
		    Some(cov) => Ok(cov.diff_new(&xencov))
		}
	};

	if *res.as_ref().unwrap() {
	    XenCov::hacky_save();
	}

	res
    }

    fn append_metadata(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observers: &OT,
        _testcase: &mut libafl::corpus::Testcase<I>,
    ) -> Result<(), libafl::Error> {
//	println!("Append metadata");

	// TODO: Store state in metadata
	let observer: &XenCovObserver = observers.get(&self.map_ref).expect("XenCovObserver not found. This is likely because you entered the crash handler with the wrong executor/observer").as_ref();

	if self.xencov.is_none() {
	    self.xencov = observer.xencov.clone();
	} else {
	    assert!(observer.xencov.is_some());
	    self.xencov.as_mut().unwrap().merge(observer.xencov.as_ref().unwrap());
	}

	if self.xencov.is_some() {
	    let (done, discovered) = self.xencov.as_mut().unwrap().get_stat();
            manager.fire(
		state,
		EventWithStats::with_current_time(
                    Event::UpdateUserStats {
			name: self.stats_name.clone(),
			value: UserStats::new(UserStatsValue::Ratio(done as u64, discovered as u64), AggregatorOps::Avg),
			phantom: PhantomData,
                    },
                    *state.executions(),
		),
            )?;
	}
        Ok(())
    }
}

impl Named for XenCovFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl XenCovFeedback {
    pub fn new(observer: &XenCovObserver) -> Self {
        Self {
            xencov: None,
            name: observer.name().clone(),
            map_ref: observer.handle(),
            stats_name: observer.name().clone(),
        }
    }
}

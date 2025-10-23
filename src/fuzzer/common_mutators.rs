/// Common mutators for hypercalls
use libafl::{
    inputs::Input,
    mutators::{MutationResult, Mutator},
    state::HasRand,
    SerdeAny,
};
use libafl_bolts::{rands::Rand, Named};

use serde::{Deserialize, Serialize};
use std::{borrow::Cow, hash::Hash};

#[derive(Debug)]
pub struct RandomDomIdMutator {}

impl<I, S> Mutator<I, S> for RandomDomIdMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, libafl::Error> {
        Ok(MutationResult::Mutated)
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }
}

impl Named for RandomDomIdMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("RandomDomIdMutator")
    }
}


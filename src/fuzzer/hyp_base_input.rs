/// Base input type for various hypercall inputs
use crate::fuzzer::generic_hypercall::GenericHypercallInput;
use crate::fuzzer::hyp_evtchn::generate_evtchn_op;

use libafl::{
    corpus::CorpusId,
    inputs::Input,
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error, SerdeAny,
};
use serde::{Deserialize, Serialize};

use crate::fuzzer::cmd_serializer::{CmdSerializable, CmdSerializer};
use libafl_bolts::{rands::Rand, Named};
use std::borrow::Cow;

#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
#[enum_delegate::implement(CmdSerializable)]
pub enum HypercallInput {
    //    EvtchnInput(EvtchnInput),
    GenericHypercall(GenericHypercallInput),
}

impl Input for HypercallInput {}

impl HypercallInput {
    pub fn gen_generic_input<S>(state: &mut S) -> HypercallInput
    where
        S: HasRand,
    {
        // TODO: Add other input types here
        Self::GenericHypercall(generate_evtchn_op(state))
    }

    pub fn generate<S>(state: &mut S) -> HypercallInput
    where
        S: HasRand,
    {
        let ctrs: Vec<fn(state: &mut S) -> HypercallInput> = vec![Self::gen_generic_input];

        state.rand_mut().choose(ctrs).unwrap()(state)
    }
}

/// Mutate one field in a hypercall
pub struct HypercallOneMutator {}

impl<S> Mutator<HypercallInput, S> for HypercallOneMutator
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut HypercallInput,
    ) -> Result<MutationResult, Error> {
        match input {
            HypercallInput::GenericHypercall(h) => Ok(h.randomize_one(state)),
        }
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for HypercallOneMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("HypercallOneMutator")
    }
}

/// Mutate all fields in a hypercall
pub struct HypercallAllMutator {}

impl<S> Mutator<HypercallInput, S> for HypercallAllMutator
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut HypercallInput,
    ) -> Result<MutationResult, Error> {
        match input {
            HypercallInput::GenericHypercall(h) => {
                h.randomize_all(state);
                Ok(MutationResult::Mutated)
            },
        }
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for HypercallAllMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("HypercallAllMutator")
    }
}

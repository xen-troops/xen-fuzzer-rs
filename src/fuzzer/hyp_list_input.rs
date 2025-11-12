use crate::fuzzer::hyp_base_input::HypercallInput;

use core::num::NonZero;
use libafl::{
    corpus::{Corpus, CorpusId},
    generators::Generator,
    inputs::{HasTargetBytes, Input, ListInput},
    mutators::{MutationResult, Mutator},
    random_corpus_id,
    state::{HasCorpus, HasMaxSize, HasRand},
    Error, SerdeAny,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::ops::{Deref, DerefMut};

use crate::fuzzer::cmd_serializer::{CmdSerializable, CmdSerializer};
use libafl_bolts::{
    rands::Rand,
    tuples::{tuple_list, tuple_list_type},
    Named,
};

#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny, Default)]
pub struct HypInputList(ListInput<HypercallInput>);

impl Input for HypInputList {}

impl HasTargetBytes for HypInputList {
    fn target_bytes(&self) -> libafl_bolts::ownedref::OwnedSlice<u8> {
        let mut serializer = CmdSerializer::new();
        for part in self.parts() {
            part.emit_cmds(&mut serializer);
        }
        libafl_bolts::ownedref::OwnedSlice::from(serializer.data)
    }
}

impl Deref for HypInputList {
    type Target = ListInput<HypercallInput>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for HypInputList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct HypercallListGenerator {
    max_inputs: NonZero<usize>,
}

impl HypercallListGenerator {
    pub fn new(max_inputs: NonZero<usize>) -> Self {
        Self { max_inputs }
    }
}

impl<S> Generator<HypInputList, S> for HypercallListGenerator
where
    S: HasRand + HasMaxSize,
{
    fn generate(&mut self, state: &mut S) -> Result<HypInputList, Error> {
        let mut input: HypInputList = Default::default();

        for _ in 0..state.rand_mut().below(self.max_inputs) {
            input.append_part(HypercallInput::generate(state));
        }

        Ok(input)
    }
}

// This is reimplementation of libafl::mutators::list, but for generic lists
pub type HypInputListMutators = tuple_list_type!(
    HypRemoveLastEntryMutator,
    HypRemoveRandomEntryMutator,
    HypCrossoverInsertMutator,
    HypCrossoverReplaceMutator,
    HypInsertMutator,
    HypReplaceMutator,
);

pub fn hyp_input_list_mutators() -> HypInputListMutators {
    tuple_list!(
        HypRemoveLastEntryMutator,
        HypRemoveRandomEntryMutator,
        HypCrossoverInsertMutator,
        HypCrossoverReplaceMutator,
	HypInsertMutator,
	HypReplaceMutator,
    )
}

/// Mutator that removes the last entry from a [`HypInputlist`].
///
/// Returns [`MutationResult::Skipped`] if the input is empty.
#[derive(Debug)]
pub struct HypRemoveLastEntryMutator;

impl<S> Mutator<HypInputList, S> for HypRemoveLastEntryMutator {
    fn mutate(
        &mut self,
        _state: &mut S,
        input: &mut HypInputList,
    ) -> Result<MutationResult, Error> {
        match input.pop_part() {
            Some(_) => Ok(MutationResult::Mutated),
            None => Ok(MutationResult::Skipped),
        }
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for HypRemoveLastEntryMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("HypRemoveLastEntryMutator")
    }
}

/// Mutator that removes a random entry from a [`HypInputlist`].
///
/// Returns [`MutationResult::Skipped`] if the input is empty.
#[derive(Debug)]
pub struct HypRemoveRandomEntryMutator;

impl<S> Mutator<HypInputList, S> for HypRemoveRandomEntryMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut HypInputList) -> Result<MutationResult, Error> {
        match input.0.len() {
            0 => Ok(MutationResult::Skipped),
            len => {
                // Safety: null checks are done above
                let index = state
                    .rand_mut()
                    .below(unsafe { NonZero::new_unchecked(len) });
                input.0.remove_part_at_index(index);
                Ok(MutationResult::Mutated)
            }
        }
    }
    #[inline]
    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for HypRemoveRandomEntryMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("HypRemoveRandomEntryMutator")
    }
}

/// Mutator that inserts a random part from another [`HypInputlist`]
/// into the current input.
#[derive(Debug)]
pub struct HypCrossoverInsertMutator;

impl<S> Mutator<HypInputList, S> for HypCrossoverInsertMutator
where
    S: HasCorpus<HypInputList> + HasMaxSize + HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut HypInputList) -> Result<MutationResult, Error> {
        let current_idx = match input.0.len() {
            0 => return Ok(MutationResult::Skipped),
            len => state
                .rand_mut()
                .below(unsafe { NonZero::new_unchecked(len) }),
        };
        let other_idx_raw = state.rand_mut().next() as usize;

        let id = random_corpus_id!(state.corpus(), state.rand_mut());
        let mut testcase = state.corpus().get(id)?.borrow_mut();
        let other = testcase.load_input(state.corpus())?;

        let other_len = other.len();

        let other_input = match other_len {
            0 => return Ok(MutationResult::Skipped),
            len => other.parts()[other_idx_raw % len].clone(),
        };

        input.insert_part(current_idx, other_input);
        Ok(MutationResult::Mutated)
    }
    #[inline]
    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for HypCrossoverInsertMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("HypCrossoverInsertMutator")
    }
}

/// Mutator that replaces a random part from the current
/// [`HypInputlist`] with a random part from another input.
#[derive(Debug)]
pub struct HypCrossoverReplaceMutator;

impl<S> Mutator<HypInputList, S> for HypCrossoverReplaceMutator
where
    S: HasCorpus<HypInputList> + HasMaxSize + HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut HypInputList) -> Result<MutationResult, Error> {
        let current_idx = match input.len() {
            0 => return Ok(MutationResult::Skipped),
            len => state
                .rand_mut()
                .below(unsafe { NonZero::new_unchecked(len) }),
        };
        let other_idx_raw = state.rand_mut().next() as usize;

        let id = random_corpus_id!(state.corpus(), state.rand_mut());
        let mut testcase = state.corpus().get(id)?.borrow_mut();
        let other = testcase.load_input(state.corpus())?;

        let other_len = other.len();

        let other_input = match other_len {
            0 => return Ok(MutationResult::Skipped),
            len => other.parts()[other_idx_raw % len].clone(),
        };

        input.remove_part_at_index(current_idx);
        input.insert_part(current_idx, other_input);
        Ok(MutationResult::Mutated)
    }
    #[inline]
    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for HypCrossoverReplaceMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("HypCrossoverReplaceMutator")
    }
}

/// Mutator that inserts a random part into the current input.
#[derive(Debug)]
pub struct HypInsertMutator;

impl<S> Mutator<HypInputList, S> for HypInsertMutator
where
    S: HasCorpus<HypInputList> + HasMaxSize + HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut HypInputList) -> Result<MutationResult, Error> {
        let current_idx = match input.0.len() {
            0 => return Ok(MutationResult::Skipped),
            len => state
                .rand_mut()
                .below(unsafe { NonZero::new_unchecked(len) }),
        };
        input.insert_part(current_idx, HypercallInput::generate(state));
        Ok(MutationResult::Mutated)
    }
    #[inline]
    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for HypInsertMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("HypInsertMutator")
    }
}

/// Mutator that replaces a random part from the current
/// [`HypInputlist`] with a new random entry
#[derive(Debug)]
pub struct HypReplaceMutator;

impl<S> Mutator<HypInputList, S> for HypReplaceMutator
where
    S: HasCorpus<HypInputList> + HasMaxSize + HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut HypInputList) -> Result<MutationResult, Error> {
        let current_idx = match input.len() {
            0 => return Ok(MutationResult::Skipped),
            len => state
                .rand_mut()
                .below(unsafe { NonZero::new_unchecked(len) }),
        };
        input.remove_part_at_index(current_idx);
        input.insert_part(current_idx, HypercallInput::generate(state));
        Ok(MutationResult::Mutated)
    }
    #[inline]
    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for HypReplaceMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("HypCrossoverReplaceMutator")
    }
}

/// Mutator that maps [`ListInput`] mutator to [`HypInputlist`]
/// mutator
#[derive(Debug)]
pub struct HypInputListMappingMutator<M> {
    inner: M,
    name: Cow<'static, str>,
}

impl<M: Named> HypInputListMappingMutator<M> {
    pub fn new(inner: M) -> Self {
        let name = Cow::Owned(format!("HypInputListMappingMutator<{}>", inner.name()));
        Self { inner, name }
    }
}

impl<M, S> Mutator<HypInputList, S> for HypInputListMappingMutator<M>
where
    M: Mutator<ListInput<HypercallInput>, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut HypInputList) -> Result<MutationResult, Error> {
        self.inner.mutate(state, &mut input.0)
    }
    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        self.inner.post_exec(state, new_corpus_id)
    }
}

impl<M> Named for HypInputListMappingMutator<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

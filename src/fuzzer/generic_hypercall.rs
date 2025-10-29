/// Base code for implementing generic hypercall info.
/// This covers hypercalls that can be data-defined
use crate::fuzzer::{
    cmd_serializer::{CmdSerializable, CmdSerializer},
    xen_bindings::{domid_t, evtchn_port_t},
};

use libafl::{
    corpus::CorpusId,
    inputs::{BytesInput, HasTargetBytes, Input},
    mutators::{
        havoc_mutations_no_crossover, scheduled::HavocScheduledMutator,
        MutationResult, Mutator,
    },
    state::{HasRand, HasMaxSize},
    Error, SerdeAny,
};
use libafl_bolts::{rands::Rand, HasLen, Named};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// Input definition
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct GenericHypercallDef {
    /// Hypercall id (i.e __HYPERVISOR_event_channel_op)
    pub id: u32,
    pub args: Vec<HypercallArg>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub enum HypercallArg {
    Const(HypercallConstArg),
    Buffer(HypercallBufferArg),
    Var(HypercallVariableArg),
}

impl HypercallArg {
    pub fn mk_const(arg_idx: u8, const_val: u64) -> Self {
        Self::Const(HypercallConstArg { arg_idx, const_val })
    }

    pub fn mk_var(arg_idx: u8, min_val: u64, max_val: u64) -> Self {
        Self::Var(HypercallVariableArg {
            arg_idx,
            min_val,
            max_val,
            cur_val: 0,
        })
    }

    pub fn mk_buffer(arg_idx: u8, size: usize, fields: Vec<HypercallBufferField>) -> Self {
        Self::Buffer(HypercallBufferArg {
            arg_idx,
            size,
            fields,
        })
    }
}

/// Hypercall type definitions

/// Hyperall constant value (i.e. op id)
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallConstArg {
    /// Argument number in hypercall
    pub arg_idx: u8,
    /// Value to be passed
    pub const_val: u64,
}

/// Hypercall buffered parameter
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferArg {
    /// Argument number in hypercall
    pub arg_idx: u8,
    /// Buffer size
    pub size: usize,
    /// Fields in this buffer
    pub fields: Vec<HypercallBufferField>,
}

impl HypercallBufferArg {
    pub fn serialize(&self) -> (Vec<u8>, Vec<usize>) {
        let mut data: Vec<u8> = vec![0; self.size];
	let mut fixups: Vec<usize> = vec![];
        for f in &self.fields {
            // TODO: Generate this with macro?
	    // TODO: Or move to impl
            match &f.data {
                HypercallBufferFieldData::DomId(d) => {
                    Self::splice(&mut data, f.offset, d.val.to_le_bytes().as_slice())
                }
                HypercallBufferFieldData::EvtchnPort(e) => {
                    Self::splice(&mut data, f.offset, e.val.to_le_bytes().as_slice())
                }
                HypercallBufferFieldData::U8(u) => {
                    Self::splice(&mut data, f.offset, u.val.to_le_bytes().as_slice())
                }
                HypercallBufferFieldData::U16(u) => {
                    Self::splice(&mut data, f.offset, u.val.to_le_bytes().as_slice())
                }
                HypercallBufferFieldData::U32(u) => {
                    Self::splice(&mut data, f.offset, u.val.to_le_bytes().as_slice())
                }
                HypercallBufferFieldData::U64(u) => {
                    Self::splice(&mut data, f.offset, u.val.to_le_bytes().as_slice())
                }
                HypercallBufferFieldData::U32Const(c) => {
                    Self::splice(&mut data, f.offset, c.val.to_le_bytes().as_slice())
                }
                HypercallBufferFieldData::Buf(b) => {
                    let buf_offset = data.len();
		    fixups.push(f.offset);
                    data.extend(&b.data.target_bytes());
                    Self::splice(&mut data, f.offset, buf_offset.to_le_bytes().as_slice());
                    if let Some(size_offset) = b.size_offset {
                        Self::splice(
                            &mut data,
                            size_offset,
                            (b.data.len() as u32).to_le_bytes().as_slice(),
                        )
                    }
                }
            }
        }
//	dbg!(self.size, data.len());
        (data, fixups)
    }

    pub fn randomize_all<S>(&mut self, state: &mut S)
    where
        S: HasRand + HasMaxSize,
    {
        for f in &mut self.fields {
            match &mut f.data {
                HypercallBufferFieldData::DomId(d) => d.randomize(state),
                HypercallBufferFieldData::EvtchnPort(e) => e.randomize(state),
                HypercallBufferFieldData::U8(u) => u.randomize(state),
                HypercallBufferFieldData::U16(u) => u.randomize(state),
                HypercallBufferFieldData::U32(u) => u.randomize(state),
                HypercallBufferFieldData::U64(u) => u.randomize(state),
                HypercallBufferFieldData::U32Const(_) => (),
                HypercallBufferFieldData::Buf(b) => b.randomize(state),
            }
        }
    }

    pub fn randomize_one<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: HasRand + HasMaxSize,
    {
        if let Some(f) = state.rand_mut().choose(&mut self.fields) {
            match &mut f.data {
                HypercallBufferFieldData::DomId(d) => {
                    d.randomize(state);
                    MutationResult::Mutated
                }
                HypercallBufferFieldData::EvtchnPort(e) => {
                    e.randomize(state);
                    MutationResult::Mutated
                }
                HypercallBufferFieldData::U8(u) => {
                    u.randomize(state);
                    MutationResult::Mutated
                }
                HypercallBufferFieldData::U16(u) => {
                    u.randomize(state);
                    MutationResult::Mutated
                }
                HypercallBufferFieldData::U32(u) => {
                    u.randomize(state);
                    MutationResult::Mutated
                }
                HypercallBufferFieldData::U64(u) => {
                    u.randomize(state);
                    MutationResult::Mutated
                }
                HypercallBufferFieldData::U32Const(_) => MutationResult::Skipped,
                HypercallBufferFieldData::Buf(b) => {
                    b.randomize(state);
                    MutationResult::Mutated
                }
            }
        } else {
            MutationResult::Skipped
        }
    }

    /// Helper for vector splicing
    fn splice(data: &mut Vec<u8>, offset: usize, new: &[u8]) {
        data.splice(offset..(offset + new.len()), new.iter().cloned());
    }
}

/// Hypercall random (mutable) value
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallVariableArg {
    pub arg_idx: u8,
    pub min_val: u64,
    pub max_val: u64,
    // Not part of definition. Used in runtime
    pub cur_val: u64,
}

/// Fields in memory buffer
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub enum HypercallBufferFieldData {
    DomId(HypercallBufferDomIdField),
    EvtchnPort(HypercallBufferEvtchnPortField),
    U8(HypercallBufferU8Field),
    U16(HypercallBufferU16Field),
    U32(HypercallBufferU32Field),
    U64(HypercallBufferU64Field),
    U32Const(HypercallBufferU32ConstField),
    Buf(HypercallBufferBufferField),
    //    String,
    //    Buf(Cow<'static, [HypercallBufferField]>),
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferField {
    /// Offset from start of the buffer. Please sort fields in the
    /// right order when creating them
    pub offset: usize,
    /// Field data
    pub data: HypercallBufferFieldData,
}

impl HypercallBufferField {
    pub const fn mk_domid_t(offset: usize) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::DomId(HypercallBufferDomIdField { val: 0 }),
        }
    }
    pub const fn mk_evtchn_port_t(offset: usize) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::EvtchnPort(HypercallBufferEvtchnPortField { val: 0 }),
        }
    }
    pub const fn mk_uint8_t(offset: usize) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::U8(HypercallBufferU8Field { val: 0 }),
        }
    }
    pub const fn mk_uint16_t(offset: usize) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::U16(HypercallBufferU16Field { val: 0 }),
        }
    }
    pub const fn mk_uint32_t(offset: usize) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::U32(HypercallBufferU32Field { val: 0 }),
        }
    }
    pub const fn mk_uint64_t(offset: usize) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::U64(HypercallBufferU64Field { val: 0 }),
        }
    }
    pub const fn mk_uint32_t_const(offset: usize, val: u32) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::U32Const(HypercallBufferU32ConstField { val }),
        }
    }

    pub const fn mk_buffer_with_size(offset: usize, size_offset: usize) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::Buf(HypercallBufferBufferField {
                size_offset: Some(size_offset),
                data: BytesInput::new(vec![]),
            }),
        }
    }
}

/// domid_t field
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferDomIdField {
    val: domid_t,
}

impl HypercallBufferDomIdField {
    // rust-bindgen is unable to parse these defines for some reason
    const DOMID_SELF: domid_t = 0x7FF0;
    const DOMID_IO: domid_t = 0x7FF1;
    const DOMID_XEN: domid_t = 0x7FF2;
    const DOMID_COW: domid_t = 0x7FF3;
    const DOMID_INVALID: domid_t = 0x7FF4;
    const DOMID_IDLE: domid_t = 0x7FFF;

    pub fn randomize<S>(&mut self, state: &mut S)
    where
        S: HasRand,
    {
        let rand = state.rand_mut();

        // Safety: list is non-empty
        self.val = rand
            .choose([
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                12,
                13,
                14,
                15,
                16,
                Self::DOMID_SELF,
                Self::DOMID_IO,
                Self::DOMID_XEN,
                Self::DOMID_COW,
                Self::DOMID_INVALID,
                Self::DOMID_IDLE,
            ])
            .unwrap();
    }
}

/// evtchn_port_t field
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferEvtchnPortField {
    val: evtchn_port_t,
}

impl HypercallBufferEvtchnPortField {
    pub fn randomize<S>(&mut self, state: &mut S)
    where
        S: HasRand,
    {
        let rand = state.rand_mut();
        self.val = rand.between(0, 64) as u32;
    }
}

///uint8_t field
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferU8Field {
    val: u8,
}

impl HypercallBufferU8Field {
    pub fn randomize<S>(&mut self, state: &mut S)
    where
        S: HasRand,
    {
        let rand = state.rand_mut();
        self.val = rand.next() as u8;
    }
}

///uint16_t field
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferU16Field {
    val: u16,
}

impl HypercallBufferU16Field {
    pub fn randomize<S>(&mut self, state: &mut S)
    where
        S: HasRand,
    {
        let rand = state.rand_mut();
        self.val = rand.next() as u16;
    }
}

///uint32_t field
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferU32Field {
    val: u32,
}

impl HypercallBufferU32Field {
    pub fn randomize<S>(&mut self, state: &mut S)
    where
        S: HasRand,
    {
        let rand = state.rand_mut();
        self.val = rand.next() as u32;
    }
}

///uint64_t field
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferU64Field {
    val: u64,
}

impl HypercallBufferU64Field {
    pub fn randomize<S>(&mut self, state: &mut S)
    where
        S: HasRand,
    {
        let rand = state.rand_mut();
        self.val = rand.next();
    }
}

///uint32_t const value
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferU32ConstField {
    val: u32,
}

///buffer ptr value
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferBufferField {
    size_offset: Option<usize>,
    data: BytesInput,
}

impl HypercallBufferBufferField {
    pub fn randomize<S>(&mut self, state: &mut S)
    where
        S: HasRand + HasMaxSize,
    {
        // Create and run havoc mutator
        let mut mutator = HavocScheduledMutator::new(havoc_mutations_no_crossover());
        let _ = Mutator::<BytesInput, S>::mutate(&mut mutator, state, &mut self.data);
    }
}

/// LibAFL-compatible Input
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct GenericHypercallInput {
    // It would be nice to have definition encoded as a type, or at
    // least as a const value and have data in the separate field.
    // But this is hard due to reasons, so let's store everything in
    // the same structure for now
    definition: GenericHypercallDef,
}

impl GenericHypercallInput {
    pub fn new<S>(definition: GenericHypercallDef, state: &mut S) -> Self
    where
        S: HasRand + HasMaxSize,
    {
        let mut res = Self { definition };

        res.randomize_all(state);

        res
    }
}

impl Input for GenericHypercallInput {}

impl HasTargetBytes for GenericHypercallInput {
    fn target_bytes(&self) -> libafl_bolts::ownedref::OwnedSlice<u8> {
        let mut serializer = CmdSerializer::new();

        self.emit_cmds(&mut serializer);

        libafl_bolts::ownedref::OwnedSlice::from(serializer.data)
    }
}

impl CmdSerializable for GenericHypercallInput {
    fn emit_cmds(&self, serializer: &mut CmdSerializer) {
        // Probably we can introduce a trait and then use enum
        // dispatch... but meh
        for f in &self.definition.args {
            match f {
                HypercallArg::Const(c) => serializer.emit_hvc_arg(c.arg_idx, c.const_val),
                HypercallArg::Var(v) => serializer.emit_hvc_arg(v.arg_idx, v.cur_val),
                HypercallArg::Buffer(b) => {
		    let (buffer, fixups) = b.serialize();
		    serializer.emit_hvc_buf(b.arg_idx, buffer.as_slice());
		    for fixup in fixups {
			serializer.emit_fixup_buf_ptr(b.arg_idx, fixup);
		    }

                }
            }
        }

        serializer.emit_hvc(self.definition.id as u64);
    }
}

impl GenericHypercallInput {
    pub fn randomize_all<S>(&mut self, state: &mut S)
    where
        S: HasRand + HasMaxSize,
    {
        for f in &mut self.definition.args {
            match f {
                HypercallArg::Const(_c) => {}
                HypercallArg::Var(v) => {
                    let rand = state.rand_mut();
                    v.cur_val = rand.between(v.min_val as usize, v.max_val as usize) as u64
                }
                HypercallArg::Buffer(b) => b.randomize_all(state),
            }
        }
    }

    pub fn randomize_one<S>(&mut self, state: &mut S) -> MutationResult
    where
        S: HasRand + HasMaxSize,
    {
        if let Some(f) = state.rand_mut().choose(&mut self.definition.args) {
            match f {
                HypercallArg::Const(_c) => MutationResult::Skipped,
                HypercallArg::Var(v) => {
                    let rand = state.rand_mut();
                    v.cur_val = rand.between(v.min_val as usize, v.max_val as usize) as u64;
                    MutationResult::Mutated
                }
                HypercallArg::Buffer(b) => b.randomize_one(state),
            }
        } else {
            MutationResult::Skipped
        }
    }
}

/// Mutators

/// Mutate one sub-value
#[derive(Debug)]
pub struct GenericHypercallOneMutator {}

impl<S> Mutator<GenericHypercallInput, S> for GenericHypercallOneMutator
where
    S: HasRand + HasMaxSize,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut GenericHypercallInput,
    ) -> Result<MutationResult, Error> {
        Ok(input.randomize_one(state))
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for GenericHypercallOneMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("GenericHypercallOneMutator")
    }
}

/// Mutate all sub-values
#[derive(Debug)]
pub struct GenericHypercallAllMutator {}

impl<S> Mutator<GenericHypercallInput, S> for GenericHypercallAllMutator
where
    S: HasRand + HasMaxSize,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut GenericHypercallInput,
    ) -> Result<MutationResult, Error> {
        input.randomize_all(state);
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for GenericHypercallAllMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("GenericHypercallAllMutator")
    }
}

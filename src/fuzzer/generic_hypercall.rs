/// Base code for implementing generic hypercall info.
/// This covers hypercalls that can be data-defined
use crate::fuzzer::{
    cmd_serializer::{CmdSerializable, CmdSerializer},
    xen_bindings::{domid_t, evtchn_port_t, xen_pfn_t},
};

use libafl::{
    corpus::CorpusId,
    inputs::{BytesInput, HasMutatorBytes, HasTargetBytes, Input},
    mutators::{
        havoc_mutations_no_crossover, scheduled::HavocScheduledMutator, BitFlipMutator,
        ByteDecMutator, ByteFlipMutator, ByteIncMutator, ByteInterestingMutator, ByteNegMutator,
        BytesRandSetMutator, BytesSetMutator, BytesSwapMutator, DwordInterestingMutator,
        MutationResult, Mutator, WordInterestingMutator,
    },
    state::{HasMaxSize, HasRand},
    Error, SerdeAny,
};
use libafl_bolts::{rands::Rand, tuples::tuple_list, HasLen, Named};
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
                HypercallBufferFieldData::XenPfn(p) => {
                    Self::splice(&mut data, f.offset, p.val.to_le_bytes().as_slice())
                }
                HypercallBufferFieldData::XenDomainHandle(h) => {
                    Self::splice(&mut data, f.offset, h.val.as_slice())
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
                HypercallBufferFieldData::U32Enum(e) => {
                    Self::splice(&mut data, f.offset, e.val.to_le_bytes().as_slice())
                }
                HypercallBufferFieldData::I32(i) => {
                    Self::splice(&mut data, f.offset, i.val.to_le_bytes().as_slice())
                }
                HypercallBufferFieldData::I64(i) => {
                    Self::splice(&mut data, f.offset, i.val.to_le_bytes().as_slice())
                }
                // TODO: Factor this out
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
                HypercallBufferFieldData::TypedBuf(b) => {
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
                HypercallBufferFieldData::XenPfn(p) => p.randomize(state),
                HypercallBufferFieldData::XenDomainHandle(h) => h.randomize(state),
                HypercallBufferFieldData::U8(u) => u.randomize(state),
                HypercallBufferFieldData::U16(u) => u.randomize(state),
                HypercallBufferFieldData::U32(u) => u.randomize(state),
                HypercallBufferFieldData::U64(u) => u.randomize(state),
                HypercallBufferFieldData::U32Const(_) => (),
                HypercallBufferFieldData::U32Enum(e) => e.randomize(state),
                HypercallBufferFieldData::I32(i) => i.randomize(state),
                HypercallBufferFieldData::I64(i) => i.randomize(state),
                HypercallBufferFieldData::Buf(b) => b.randomize(state),
                HypercallBufferFieldData::TypedBuf(b) => b.randomize(state),
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
                HypercallBufferFieldData::XenPfn(p) => {
                    p.randomize(state);
                    MutationResult::Mutated
                }
                HypercallBufferFieldData::XenDomainHandle(h) => {
                    h.randomize(state);
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
                HypercallBufferFieldData::U32Enum(e) => {
                    e.randomize(state);
                    MutationResult::Mutated
                }
                HypercallBufferFieldData::I32(i) => {
                    i.randomize(state);
                    MutationResult::Mutated
                }
                HypercallBufferFieldData::I64(i) => {
                    i.randomize(state);
                    MutationResult::Mutated
                }
                HypercallBufferFieldData::Buf(b) => {
                    b.randomize(state);
                    MutationResult::Mutated
                }
                HypercallBufferFieldData::TypedBuf(b) => {
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
    XenPfn(HypercallBufferXenPfnField),
    XenDomainHandle(HypercallBufferXenDomainHandleField),
    U8(HypercallBufferU8Field),
    U16(HypercallBufferU16Field),
    U32(HypercallBufferU32Field),
    U64(HypercallBufferU64Field),
    U32Const(HypercallBufferU32ConstField),
    U32Enum(HypercallBufferU32EnumField),
    I32(HypercallBufferI32Field),
    I64(HypercallBufferI64Field),
    Buf(HypercallBufferBufferField),
    TypedBuf(HypercallBufferTypedBufferField),
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
    pub const fn mk_xen_pfn_t(offset: usize) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::XenPfn(HypercallBufferXenPfnField { val: 0 }),
        }
    }
    pub const fn mk_xen_domain_handle_t(offset: usize) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::XenDomainHandle(HypercallBufferXenDomainHandleField {
                val: [0; 16],
            }),
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
    pub const fn mk_uint32_t_enum(offset: usize, possible_vals: Vec<u32>) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::U32Enum(HypercallBufferU32EnumField {
                val: 0,
                possible_vals,
            }),
        }
    }
    pub const fn mk_int32_t(offset: usize) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::I32(HypercallBufferI32Field { val: 0 }),
        }
    }
    pub const fn mk_int64_t(offset: usize) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::I64(HypercallBufferI64Field { val: 0 }),
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
    pub const fn mk_buffer_wo_size(offset: usize) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::Buf(HypercallBufferBufferField {
                size_offset: None,
                data: BytesInput::new(vec![]),
            }),
        }
    }
    pub const fn mk_typed_buffer_with_size(
        offset: usize,
        item_size: usize,
        size_offset: usize,
    ) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::TypedBuf(HypercallBufferTypedBufferField::new(
                item_size,
                Some(size_offset),
            )),
        }
    }
    pub const fn mk_typed_buffer_wo_size(offset: usize, item_size: usize) -> Self {
        Self {
            offset,
            data: HypercallBufferFieldData::TypedBuf(HypercallBufferTypedBufferField::new(
                item_size, None,
            )),
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

/// xen_pfn_t field
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferXenPfnField {
    val: xen_pfn_t,
}

impl HypercallBufferXenPfnField {
    // rust-bindgen is unable to parse these defines for some reason
    const GUEST_RAM0_BASE: u64 = 0x40000000;
    const GUEST_RAM1_BASE: u64 = 0x0200000000;

    pub fn randomize<S>(&mut self, state: &mut S)
    where
        S: HasRand,
    {
        let rand = state.rand_mut();

        // Let's choose interesting PFNs
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
                0x1000000,
                0x2000000,
                Self::GUEST_RAM0_BASE / 4096,
                Self::GUEST_RAM0_BASE / 4096 + 128,
                Self::GUEST_RAM0_BASE / 4096 + 256,
                Self::GUEST_RAM0_BASE / 4096 + 1024,
                Self::GUEST_RAM1_BASE / 4096,
                Self::GUEST_RAM1_BASE / 4096 + 128,
                Self::GUEST_RAM1_BASE / 4096 + 256,
                Self::GUEST_RAM1_BASE / 4096 + 1024,
                0xFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ])
            .unwrap();
    }
}

/// xen_domain_handle_t field
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferXenDomainHandleField {
    val: [u8; 16],
}

impl HypercallBufferXenDomainHandleField {
    pub fn randomize<S>(&mut self, state: &mut S)
    where
        S: HasRand,
    {
        let rand = state.rand_mut();

        // This is boring UUID, so let's just use set of some UUIDs
        let interesting_uuids: [[u8; 16]; 4] = [
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF,
            ],
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
            [
                0xee, 0xa1, 0xad, 0xb1, 0x1c, 0xf6, 0x41, 0x6a, 0x97, 0x33, 0xfd, 0xed, 0x50, 0x3a,
                0xca, 0xb5,
            ],
        ];

        self.val = rand.choose(interesting_uuids).unwrap();
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

///uint32_t enum value
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferU32EnumField {
    val: u32,
    possible_vals: Vec<u32>,
}

impl HypercallBufferU32EnumField {
    pub fn randomize<S>(&mut self, state: &mut S)
    where
        S: HasRand,
    {
        let rand = state.rand_mut();
        // Safety: expected that user provid non-empty array
        self.val = *rand.choose(self.possible_vals.as_slice()).unwrap();
    }
}

///int32_t field
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferI32Field {
    val: i32,
}

impl HypercallBufferI32Field {
    pub fn randomize<S>(&mut self, state: &mut S)
    where
        S: HasRand,
    {
        let rand = state.rand_mut();
        self.val = rand.next() as i32;
    }
}

///int64_t field
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferI64Field {
    val: i64,
}

impl HypercallBufferI64Field {
    pub fn randomize<S>(&mut self, state: &mut S)
    where
        S: HasRand,
    {
        let rand = state.rand_mut();
        self.val = rand.next() as i64;
    }
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

///buffer ptr value but for better structs
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct HypercallBufferTypedBufferField {
    size_offset: Option<usize>,
    item_size: usize,
    data: BytesInput,
}

impl HypercallBufferTypedBufferField {
    pub const fn new(item_size: usize, size_offset: Option<usize>) -> Self {
        Self {
            item_size,
            size_offset,
            data: BytesInput::new(vec![]),
        }
    }
    pub fn randomize<S>(&mut self, state: &mut S)
    where
        S: HasRand + HasMaxSize,
    {
        // Check size (and resize if needed)
        if self.data.len() != self.item_size {
            libafl::inputs::ResizableMutator::resize(&mut self.data, self.item_size, 0);
            let rand = state.rand_mut();

            // Help further mutations with generating initial data
            for i in 0..self.data.len() {
                self.data.mutator_bytes_mut()[i] =
                    rand.below(std::num::NonZero::new(256 as usize).unwrap()) as u8;
            }
        }

        // Create and run havoc mutator
        let mut mutator = HavocScheduledMutator::new(tuple_list!(
            BitFlipMutator::new(),
            ByteFlipMutator::new(),
            ByteIncMutator::new(),
            ByteDecMutator::new(),
            ByteNegMutator::new(),
            ByteInterestingMutator::new(),
            WordInterestingMutator::new(),
            DwordInterestingMutator::new(),
            BytesSetMutator::new(),
            BytesRandSetMutator::new(),
            BytesSwapMutator::new(),
        ));
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

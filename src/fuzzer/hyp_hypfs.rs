use crate::fuzzer::generic_hypercall::*;

use crate::fuzzer::xen_bindings::*;
use crate::{hypercall, hypercall_arg};
use libafl::state::{HasMaxSize, HasRand};
use libafl_bolts::rands::Rand;
use paste::paste;

const CTRS: &'static [fn() -> GenericHypercallDef] = &[mk_hypfs_get_version, mk_hypfs_read];

hypercall! {hypfs_get_version, __HYPERVISOR_hypfs_op,
    hypercall_arg!{0, const XEN_HYPFS_OP_get_version}
}

hypercall! {hypfs_read, __HYPERVISOR_hypfs_op,
    hypercall_arg!{0, const XEN_HYPFS_OP_read},
    hypercall_arg!{1, const 0},
    hypercall_arg!{2, const 0},
    hypercall_arg!{3, struct xen_hypfs_direntry,},
    hypercall_arg!{4, const 1024}
}

pub fn generate_hypfs_op<S>(state: &mut S) -> GenericHypercallInput
where
    S: HasRand + HasMaxSize,
{
    // Safety: CTRS are nonempty
    GenericHypercallInput::new(state.rand_mut().choose(CTRS).unwrap()(), state)
}

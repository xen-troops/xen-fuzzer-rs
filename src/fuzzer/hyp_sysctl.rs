use crate::fuzzer::generic_hypercall::*;

use crate::fuzzer::xen_bindings::*;
use crate::{hypercall, hypercall_arg, hypercall_struct_field};
use libafl::state::{HasMaxSize, HasRand};
use libafl_bolts::rands::Rand;
use paste::paste;
use std::mem::offset_of;

const CTRS: &'static [fn() -> GenericHypercallDef] = &[mk_sysctl_read_console];

hypercall! {sysctl_read_console, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
               hypercall_struct_field! {const xen_sysctl:cmd (uint32_t) =
                        XEN_SYSCTL_readconsole},
               hypercall_struct_field! {const xen_sysctl:interface_version (uint32_t) =
                        XEN_SYSCTL_INTERFACE_VERSION},
               hypercall_struct_field! {var xen_sysctl:u.readconsole.clear (uint8_t)},
               hypercall_struct_field! {var xen_sysctl:u.readconsole.incremental (uint8_t)},
               hypercall_struct_field! {var xen_sysctl:u.readconsole.index (uint32_t)},
               hypercall_struct_field! {buf_with_size xen_sysctl:u.readconsole.buffer =>
                        u.readconsole.count}
        }
}

pub fn generate_sysctl_op<S>(state: &mut S) -> GenericHypercallInput
where
    S: HasRand + HasMaxSize,
{
    // Safety: CTRS are nonempty
    GenericHypercallInput::new(state.rand_mut().choose(CTRS).unwrap()(), state)
}

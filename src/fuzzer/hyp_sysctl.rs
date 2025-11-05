use crate::fuzzer::generic_hypercall::*;

use crate::fuzzer::xen_bindings::*;
use crate::{hypercall, hypercall_arg, hypercall_struct_field};
use libafl::state::{HasMaxSize, HasRand};
use libafl_bolts::rands::Rand;
use paste::paste;
use std::mem::offset_of;

const CTRS: &'static [fn() -> GenericHypercallDef] = &[
    mk_sysctl_read_console,
    mk_sysctl_tbuf_op,
    mk_sysctl_physinfo,
    mk_sysctl_sched_id,
    mk_sysctl_perfc_op,
];

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

// TODO: Implement special buffer arg type for sized items
hypercall! {sysctl_tbuf_op, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
               hypercall_struct_field! {const xen_sysctl:cmd (uint32_t) =
                        XEN_SYSCTL_tbuf_op},
               hypercall_struct_field! {const xen_sysctl:interface_version (uint32_t) =
                    XEN_SYSCTL_INTERFACE_VERSION},
               hypercall_struct_field!{enum xen_sysctl:u.tbuf_op.cmd (uint32_t)
                           [XEN_SYSCTL_TBUFOP_get_info,
                            XEN_SYSCTL_TBUFOP_set_cpu_mask,
                            XEN_SYSCTL_TBUFOP_set_evt_mask,
			    XEN_SYSCTL_TBUFOP_set_size,
			    XEN_SYSCTL_TBUFOP_enable,
			    XEN_SYSCTL_TBUFOP_disable]},
               hypercall_struct_field! {buf_wo_size xen_sysctl:u.tbuf_op.cpu_mask.bitmap},
               hypercall_struct_field! {var xen_sysctl:u.tbuf_op.cpu_mask.nr_bits (uint32_t)},
               hypercall_struct_field! {var xen_sysctl:u.tbuf_op.buffer_mfn (uint64_t)},
               hypercall_struct_field! {var xen_sysctl:u.tbuf_op.size (uint32_t)}
    }
}

hypercall! {sysctl_physinfo, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
               hypercall_struct_field! {const xen_sysctl:cmd (uint32_t) =
                        XEN_SYSCTL_physinfo},
               hypercall_struct_field! {const xen_sysctl:interface_version (uint32_t) =
                    XEN_SYSCTL_INTERFACE_VERSION}
    }
}

hypercall! {sysctl_sched_id, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
               hypercall_struct_field! {const xen_sysctl:cmd (uint32_t) =
                        XEN_SYSCTL_sched_id},
               hypercall_struct_field! {const xen_sysctl:interface_version (uint32_t) =
                    XEN_SYSCTL_INTERFACE_VERSION}
    }
}

// TODO: Implement special buffer arg type for sized items for OUT buffers
hypercall! {sysctl_perfc_op, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
               hypercall_struct_field! {const xen_sysctl:cmd (uint32_t) =
                        XEN_SYSCTL_perfc_op},
               hypercall_struct_field! {const xen_sysctl:interface_version (uint32_t) =
                    XEN_SYSCTL_INTERFACE_VERSION},
               hypercall_struct_field!{enum xen_sysctl:u.perfc_op.cmd (uint32_t)
				       [XEN_SYSCTL_PERFCOP_reset, XEN_SYSCTL_PERFCOP_query]},
               hypercall_struct_field! {buf_wo_size xen_sysctl:u.perfc_op.desc},
               hypercall_struct_field! {buf_wo_size xen_sysctl:u.perfc_op.val}
    }
}

pub fn generate_sysctl_op<S>(state: &mut S) -> GenericHypercallInput
where
    S: HasRand + HasMaxSize,
{
    // Safety: CTRS are nonempty
    GenericHypercallInput::new(state.rand_mut().choose(CTRS).unwrap()(), state)
}

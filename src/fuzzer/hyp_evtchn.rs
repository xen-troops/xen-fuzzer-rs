use crate::fuzzer::generic_hypercall::*;
/// __HYPERVISOR_event_channel_op hypercalls are defined here
use crate::fuzzer::xen_bindings::{
    evtchn_alloc_unbound, evtchn_bind_interdomain, evtchn_close, EVTCHNOP_alloc_unbound,
    EVTCHNOP_bind_interdomain, EVTCHNOP_close, __HYPERVISOR_event_channel_op,
};

use crate::{hypercall, hypercall_arg};
use libafl::state::HasRand;
use libafl_bolts::rands::Rand;
use paste::paste;
use std::mem::offset_of;

const CTRS: &'static [fn() -> GenericHypercallDef] = &[
    mk_evtchn_bind_interdomain,
    mk_evtchn_alloc_unbound,
    mk_evtchn_close,
];

// fn mk_evtchn_bind_interdomain() -> GenericHypercallDef {
//     GenericHypercallDef {
//         id: __HYPERVISOR_event_channel_op,
//         args: vec![
//             HypercallArg::mk_const(0, EVTCHNOP_bind_interdomain as u64),
//             HypercallArg::mk_buffer(
//                 1,
//                 size_of::<evtchn_bind_interdomain>(),
//                 vec![
//                     HypercallBufferField::mk_domid_t(offset_of!(evtchn_bind_interdomain, remote_dom)),
//                     HypercallBufferField::mk_evtchn_port_t(offset_of!(
//                         evtchn_bind_interdomain,
//                         remote_port
//                     )),
//                 ],
//             ),
//         ],
//     }
// }

hypercall! {evtchn_bind_interdomain, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_bind_interdomain},
        hypercall_arg!{1, struct evtchn_bind_interdomain,
               domid_t remote_dom,
               evtchn_port_t remote_port
        }
}

hypercall! {evtchn_close, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_close},
        hypercall_arg!{1, struct evtchn_close,
               evtchn_port_t port
        }
}

hypercall! {evtchn_alloc_unbound, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_alloc_unbound},
        hypercall_arg!{1, struct evtchn_alloc_unbound,
               domid_t dom,
               domid_t remote_dom
        }
}

pub fn generate_evtchn_op<S>(state: &mut S) -> GenericHypercallInput
where
    S: HasRand,
{
    // Safety: CTRS are nonempty
    GenericHypercallInput::new(state.rand_mut().choose(CTRS).unwrap()(), state)
}

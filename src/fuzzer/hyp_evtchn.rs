use crate::fuzzer::generic_hypercall::*;
/// __HYPERVISOR_event_channel_op hypercalls are defined here
use crate::fuzzer::xen_bindings::{
    EVTCHNOP_alloc_unbound, EVTCHNOP_bind_interdomain, EVTCHNOP_bind_ipi, EVTCHNOP_bind_pirq,
    EVTCHNOP_bind_vcpu, EVTCHNOP_bind_virq, EVTCHNOP_close, EVTCHNOP_expand_array,
    EVTCHNOP_init_control, EVTCHNOP_reset, EVTCHNOP_send, EVTCHNOP_set_priority, EVTCHNOP_status,
    EVTCHNOP_unmask, __HYPERVISOR_event_channel_op, evtchn_alloc_unbound, evtchn_bind_interdomain,
    evtchn_bind_ipi, evtchn_bind_pirq, evtchn_bind_vcpu, evtchn_bind_virq, evtchn_close,
    evtchn_expand_array, evtchn_init_control, evtchn_reset, evtchn_send, evtchn_set_priority,
    evtchn_status, evtchn_unmask,
};

use crate::{hypercall, hypercall_arg};
use libafl::state::{HasRand, HasMaxSize};
use libafl_bolts::rands::Rand;
use paste::paste;
use std::mem::offset_of;

const CTRS: &'static [fn() -> GenericHypercallDef] = &[
    mk_evtchn_alloc_unbound,
    mk_evtchn_bind_interdomain,
    mk_evtchn_bind_virq,
    mk_evtchn_bind_pirq,
    mk_evtchn_bind_ipi,
    mk_evtchn_close,
    mk_evtchn_send,
    mk_evtchn_status,
    mk_evtchn_bind_vcpu,
    mk_evtchn_unmask,
    mk_evtchn_reset,
    mk_evtchn_init_control,
    mk_evtchn_expand_array,
    mk_evtchn_set_priority,
];

hypercall! {evtchn_alloc_unbound, __HYPERVISOR_event_channel_op,
    hypercall_arg!{0, const EVTCHNOP_alloc_unbound},
        hypercall_arg!{1, struct evtchn_alloc_unbound,
                domid_t dom,
                domid_t remote_dom,
                evtchn_port_t port
        }
}

hypercall! {evtchn_bind_interdomain, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_bind_interdomain},
        hypercall_arg!{1, struct evtchn_bind_interdomain,
                domid_t remote_dom,
                evtchn_port_t remote_port,
                evtchn_port_t local_port
        }
}

hypercall! {evtchn_bind_virq, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_bind_virq},
        hypercall_arg!{1, struct evtchn_bind_virq,
                uint32_t virq,
                uint32_t vcpu,
                evtchn_port_t port
        }
}

hypercall! {evtchn_bind_pirq, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_bind_pirq},
        hypercall_arg!{1, struct evtchn_bind_pirq,
                uint32_t pirq,
                uint32_t flags,
                evtchn_port_t port
        }
}

hypercall! {evtchn_bind_ipi, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_bind_ipi},
        hypercall_arg!{1, struct evtchn_bind_ipi,
                uint32_t vcpu,
                evtchn_port_t port
        }
}

hypercall! {evtchn_close, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_close},
        hypercall_arg!{1, struct evtchn_close,
                evtchn_port_t port
        }
}

hypercall! {evtchn_send, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_send},
        hypercall_arg!{1, struct evtchn_send,
                evtchn_port_t port
        }
}

hypercall! {evtchn_status, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_status},
        hypercall_arg!{1, struct evtchn_status,
                domid_t dom,
                evtchn_port_t port,
                uint32_t status,
                uint32_t vcpu
        }
}

hypercall! {evtchn_bind_vcpu, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_bind_vcpu},
        hypercall_arg!{1, struct evtchn_bind_vcpu,
                evtchn_port_t port,
                uint32_t vcpu
        }
}

hypercall! {evtchn_unmask, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_unmask},
        hypercall_arg!{1, struct evtchn_unmask,
                evtchn_port_t port
        }
}

hypercall! {evtchn_reset, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_reset},
        hypercall_arg!{1, struct evtchn_reset,
                domid_t dom
        }
}

hypercall! {evtchn_init_control, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_init_control},
        hypercall_arg!{1, struct evtchn_init_control,
                uint64_t control_gfn,
                uint32_t offset,
                uint32_t vcpu,
                uint8_t link_bits
        }
}

hypercall! {evtchn_expand_array, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_expand_array},
        hypercall_arg!{1, struct evtchn_expand_array,
                uint64_t array_gfn
        }
}

hypercall! {evtchn_set_priority, __HYPERVISOR_event_channel_op,
        hypercall_arg!{0, const EVTCHNOP_set_priority},
        hypercall_arg!{1, struct evtchn_set_priority,
                evtchn_port_t port,
                uint32_t priority
        }
}

pub fn generate_evtchn_op<S>(state: &mut S) -> GenericHypercallInput
where
    S: HasRand + HasMaxSize,
{
    // Safety: CTRS are nonempty
    GenericHypercallInput::new(state.rand_mut().choose(CTRS).unwrap()(), state)
}

use crate::fuzzer::generic_hypercall::*;

use crate::fuzzer::xen_bindings::*;
use crate::{hypercall, hypercall_arg, hypercall_struct_field};
use libafl::state::{HasMaxSize, HasRand};
use libafl_bolts::rands::Rand;
use paste::paste;
use std::mem::offset_of;

const CTRS: &'static [fn() -> GenericHypercallDef] = &[
    mk_flask_load,
    mk_flask_getenforce,
    mk_flask_setenforce,
    mk_flask_context_to_sid,
    mk_flask_sid_to_context,
    mk_flask_access,
    mk_flask_create,
    mk_flask_member,
    mk_flask_getbool,
    mk_flask_setbool,
    mk_flask_setavc_threshold,
    mk_flask_avc_hashstats,
    mk_flask_avc_cachestats,
    mk_flask_add_ocontext,
    mk_flask_del_ocontext,
    mk_flask_get_peer_sid,
    mk_flask_relabel,
    mk_flask_devicetree_label,
];

hypercall! {flask_load, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_LOAD},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{buf_with_size xen_flask_op:u.load.buffer => u.load.size}
        }
}

hypercall! {flask_getenforce, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_GETENFORCE},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.enforce.enforcing (uint32_t)}
        }
}

hypercall! {flask_setenforce, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_SETENFORCE},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.enforce.enforcing (uint32_t)}
        }
}

hypercall! {flask_context_to_sid, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_CONTEXT_TO_SID},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.sid_context.sid (uint32_t)},
            hypercall_struct_field!{buf_with_size xen_flask_op:u.sid_context.context => u.sid_context.size}
        }
}

hypercall! {flask_sid_to_context, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_SID_TO_CONTEXT},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.sid_context.sid (uint32_t)},
            hypercall_struct_field!{buf_with_size xen_flask_op:u.sid_context.context => u.sid_context.size}
        }
}

hypercall! {flask_access, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_ACCESS},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.access.ssid (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.access.tsid (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.access.tclass (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.access.req (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.access.allowed (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.access.audit_allow (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.access.audit_deny (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.access.seqno (uint32_t)}
        }
}

hypercall! {flask_create, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_CREATE},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.transition.ssid (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.transition.tsid (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.transition.tclass (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.transition.newsid (uint32_t)}
        }
}

hypercall! {flask_member, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_MEMBER},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.transition.ssid (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.transition.tsid (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.transition.tclass (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.transition.newsid (uint32_t)}
        }
}

hypercall! {flask_getbool, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_GETBOOL},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.boolean.bool_id (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.boolean.enforcing (uint8_t)},
            hypercall_struct_field!{var xen_flask_op:u.boolean.pending (uint8_t)},
            hypercall_struct_field!{var xen_flask_op:u.boolean.new_value (uint8_t)},
            hypercall_struct_field!{var xen_flask_op:u.boolean.commit (uint8_t)},
            hypercall_struct_field!{buf_with_size xen_flask_op:u.boolean.name => u.boolean.size}
        }
}

hypercall! {flask_setbool, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_SETBOOL},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.boolean.bool_id (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.boolean.enforcing (uint8_t)},
            hypercall_struct_field!{var xen_flask_op:u.boolean.pending (uint8_t)},
            hypercall_struct_field!{var xen_flask_op:u.boolean.new_value (uint8_t)},
            hypercall_struct_field!{var xen_flask_op:u.boolean.commit (uint8_t)},
            hypercall_struct_field!{buf_with_size xen_flask_op:u.boolean.name => u.boolean.size}
        }
}

hypercall! {flask_setavc_threshold, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_SETAVC_THRESHOLD},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.setavc_threshold.threshold (uint32_t)}
        }
}

hypercall! {flask_avc_hashstats, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_AVC_HASHSTATS},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.hash_stats.entries (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.hash_stats.buckets_used (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.hash_stats.buckets_total (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.hash_stats.max_chain_len (uint32_t)}
        }
}

hypercall! {flask_avc_cachestats, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_AVC_CACHESTATS},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.cache_stats.cpu (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.cache_stats.lookups (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.cache_stats.hits (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.cache_stats.misses (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.cache_stats.allocations (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.cache_stats.reclaims (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.cache_stats.frees (uint32_t)}
        }
}

hypercall! {flask_add_ocontext, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_ADD_OCONTEXT},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.ocontext.ocon (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.ocontext.sid (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.ocontext.low (uint64_t)},
            hypercall_struct_field!{var xen_flask_op:u.ocontext.high (uint64_t)}
        }
}

hypercall! {flask_del_ocontext, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_DEL_OCONTEXT},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.ocontext.ocon (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.ocontext.sid (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.ocontext.low (uint64_t)},
            hypercall_struct_field!{var xen_flask_op:u.ocontext.high (uint64_t)}
        }
}

hypercall! {flask_get_peer_sid, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_GET_PEER_SID},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.peersid.evtchn (evtchn_port_t)},
            hypercall_struct_field!{var xen_flask_op:u.peersid.sid (uint32_t)}
        }
}

hypercall! {flask_relabel, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_RELABEL},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.relabel.domid (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.relabel.sid (uint32_t)}
        }
}

hypercall! {flask_devicetree_label, __HYPERVISOR_xsm_op,
        hypercall_arg!{0, complex_struct xen_flask_op,
            hypercall_struct_field!{const xen_flask_op:cmd (uint32_t) = FLASK_DEVICETREE_LABEL},
            hypercall_struct_field!{const xen_flask_op:interface_version (uint32_t) = XEN_FLASK_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_flask_op:u.devicetree_label.sid (uint32_t)},
            hypercall_struct_field!{var xen_flask_op:u.devicetree_label.length (uint32_t)},
            hypercall_struct_field!{buf_wo_size xen_flask_op:u.devicetree_label.path}
        }
}

pub fn generate_flask_op<S>(state: &mut S) -> GenericHypercallInput
where
    S: HasRand + HasMaxSize,
{
    // Safety: CTRS are nonempty
    GenericHypercallInput::new(state.rand_mut().choose(CTRS).unwrap()(), state)
}

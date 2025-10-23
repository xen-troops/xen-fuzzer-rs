use crate::fuzzer::xen_bindings::{
    domid_t, evtchn_alloc_unbound, evtchn_bind_interdomain, evtchn_port_t, EVTCHNOP_alloc_unbound,
    EVTCHNOP_bind_interdomain, __HYPERVISOR_event_channel_op,
};
use std::mem;

use libafl::{
    inputs::Input,
    mutators::{MutationResult, Mutator},
    state::HasRand,
    SerdeAny,
};
use libafl_bolts::{rands::Rand, Named};

use serde::{Deserialize, Serialize};
use std::{borrow::Cow, hash::Hash};

use crate::fuzzer::cmd_serializer::{CmdSerializable, CmdSerializer};

#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
#[enum_delegate::implement(CmdSerializable)]
pub enum EvtchnInput {
    AllocUnbound(AllocUnbound),
    BindInterdomain(BindInterdomain),
}

impl Input for EvtchnInput {}

/// Super "class" for event channel ops
impl EvtchnInput {
    pub fn create_random<S>(state: &mut S) -> EvtchnInput
    where
        S: HasRand,
    {
        let ctrs: Vec<fn(state: &mut S) -> EvtchnInput> =
            vec![Self::rand_alloc_unbound, Self::rand_bind_interdomain];

        state.rand_mut().choose(ctrs).unwrap()(state)
    }

    pub fn rand_alloc_unbound<S>(state: &mut S) -> EvtchnInput
    where
        S: HasRand,
    {
        let rand = state.rand_mut();
        let dom = rand.next() as domid_t;
        let remote_dom = rand.next() as domid_t;

        EvtchnInput::AllocUnbound(AllocUnbound { dom, remote_dom })
    }

    pub fn rand_bind_interdomain<S>(state: &mut S) -> EvtchnInput
    where
        S: HasRand,
    {
        let rand = state.rand_mut();
        let remote_dom = rand.next() as domid_t;
        let remote_port = rand.next() as evtchn_port_t;

        EvtchnInput::BindInterdomain(BindInterdomain {
            remote_dom,
            remote_port,
        })
    }
}

fn get_bytes<T>(data: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(data as *const T as *const u8, mem::size_of::<T>()) }
}

/// EVTCHNOP_bind_interdomain hypcall
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct BindInterdomain {
    remote_dom: domid_t,
    remote_port: evtchn_port_t,
}

impl CmdSerializable for BindInterdomain {
    fn emit_cmds(&self, serializer: &mut CmdSerializer) {
        let bind = evtchn_bind_interdomain {
            remote_dom: self.remote_dom,
            remote_port: self.remote_port,
            local_port: 0,
        };

        serializer.emit_hvc_arg(0, EVTCHNOP_bind_interdomain as u64);
        serializer.emit_hvc_buf(1, get_bytes(&bind));
        serializer.emit_hvc(__HYPERVISOR_event_channel_op as u64);
    }
}



// Example if we'll need it
// impl HasTargetBytes for BindInterdomain {
//     fn target_bytes(&self) -> libafl_bolts::ownedref::OwnedSlice<u8> {
//         let mut serializer = CmdSerializer::new();

// 	self.emit_cmds(&mut serializer);

//         libafl_bolts::ownedref::OwnedSlice::from(serializer.data)
//     }
// }

/// EVTCHNOP_alloc_unbound hypcall
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct AllocUnbound {
    dom: domid_t,
    remote_dom: domid_t,
}

impl CmdSerializable for AllocUnbound {
    fn emit_cmds(&self, serializer: &mut CmdSerializer) {
        let alloc = evtchn_alloc_unbound {
            dom: self.dom,
            remote_dom: self.remote_dom,
            port: 0,
        };

        serializer.emit_hvc_arg(0, EVTCHNOP_alloc_unbound as u64);
        serializer.emit_hvc_buf(1, get_bytes(&alloc));

        serializer.emit_hvc(__HYPERVISOR_event_channel_op as u64);
    }
}

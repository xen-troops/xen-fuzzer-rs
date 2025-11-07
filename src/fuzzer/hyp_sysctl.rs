use crate::fuzzer::generic_hypercall::*;

use crate::fuzzer::xen_bindings::*;
use crate::{hypercall, hypercall_arg, hypercall_struct_field};
use libafl::state::{HasMaxSize, HasRand};
use libafl_bolts::rands::Rand;
use paste::paste;
use std::mem::offset_of;

const CTRS: &'static [fn() -> GenericHypercallDef] = &[
    mk_xen_sysctl_readconsole,
    mk_xen_sysctl_tbuf_op,
    mk_xen_sysctl_physinfo,
    mk_xen_sysctl_cputopoinfo,
    mk_xen_sysctl_pcitopoinfo,
    mk_xen_sysctl_numainfo,
    mk_xen_sysctl_sched_id,
    mk_xen_sysctl_perfc_op,
    mk_xen_sysctl_getdomaininfolist,
    mk_xen_sysctl_debug_keys,
    mk_xen_sysctl_getcpuinfo,
    mk_xen_sysctl_availheap,
    mk_xen_sysctl_cpu_hotplug,
    mk_xen_sysctl_page_offline_op,
    mk_xen_sysctl_lockprof_op,
    mk_xen_sysctl_cpupool_op,
    mk_xen_sysctl_coverage_op,
    mk_xen_sysctl_cpu_levelling_caps,
    mk_xen_sysctl_cpu_featureset,
    mk_xen_sysctl_dt_overlay,
];

hypercall! {xen_sysctl_readconsole, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_readconsole},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.readconsole.clear (uint8_t)},
            hypercall_struct_field!{var xen_sysctl:u.readconsole.incremental (uint8_t)},
            hypercall_struct_field!{var xen_sysctl:u.readconsole.index (uint32_t)},
            hypercall_struct_field!{buf_with_size xen_sysctl:u.readconsole.buffer => u.readconsole.count}
        }
}

hypercall! {xen_sysctl_tbuf_op, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_tbuf_op},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.tbuf_op.cmd (uint32_t)},
            hypercall_struct_field!{buf_wo_size xen_sysctl:u.tbuf_op.cpu_mask.bitmap},
            hypercall_struct_field!{var xen_sysctl:u.tbuf_op.cpu_mask.nr_bits (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.tbuf_op.evt_mask (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.tbuf_op.buffer_mfn (uint64_t)},
            hypercall_struct_field!{var xen_sysctl:u.tbuf_op.size (uint32_t)}
        }
}

hypercall! {xen_sysctl_physinfo, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_physinfo},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.physinfo.threads_per_core (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.physinfo.cores_per_socket (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.physinfo.nr_cpus (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.physinfo.max_cpu_id (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.physinfo.nr_nodes (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.physinfo.max_node_id (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.physinfo.cpu_khz (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.physinfo.capabilities (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.physinfo.arch_capabilities (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.physinfo.total_pages (uint64_t)},
            hypercall_struct_field!{var xen_sysctl:u.physinfo.free_pages (uint64_t)},
            hypercall_struct_field!{var xen_sysctl:u.physinfo.scrub_pages (uint64_t)},
            hypercall_struct_field!{var xen_sysctl:u.physinfo.outstanding_pages (uint64_t)},
            hypercall_struct_field!{var xen_sysctl:u.physinfo.max_mfn (uint64_t)}
        }
}

hypercall! {xen_sysctl_cputopoinfo, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_cputopoinfo},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.cputopoinfo.num_cpus (uint32_t)},
            hypercall_struct_field!{typed_buf_wo_size xen_sysctl:u.cputopoinfo.cputopo (xen_sysctl_cputopo_t)}
        }
}

hypercall! {xen_sysctl_pcitopoinfo, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_pcitopoinfo},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.pcitopoinfo.num_devs (uint32_t)},
            hypercall_struct_field!{typed_buf_wo_size xen_sysctl:u.pcitopoinfo.devs (physdev_pci_device_t)},
            hypercall_struct_field!{typed_buf_wo_size xen_sysctl:u.pcitopoinfo.nodes (u32)}
        }
}

hypercall! {xen_sysctl_numainfo, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_numainfo},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.numainfo.num_nodes (uint32_t)},
            hypercall_struct_field!{typed_buf_wo_size xen_sysctl:u.numainfo.meminfo (xen_sysctl_meminfo_t)},
            hypercall_struct_field!{typed_buf_wo_size xen_sysctl:u.numainfo.distance (u32)}
        }
}

hypercall! {xen_sysctl_sched_id, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_sched_id},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.sched_id.sched_id (uint32_t)}
        }
}

hypercall! {xen_sysctl_perfc_op, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_perfc_op},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.perfc_op.cmd (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.perfc_op.nr_counters (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.perfc_op.nr_vals (uint32_t)},
            hypercall_struct_field!{typed_buf_wo_size xen_sysctl:u.perfc_op.desc (xen_sysctl_perfc_desc_t)},
            hypercall_struct_field!{typed_buf_wo_size xen_sysctl:u.perfc_op.val (xen_sysctl_perfc_val_t)}
        }
}

hypercall! {xen_sysctl_getdomaininfolist, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_getdomaininfolist},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.getdomaininfolist.first_domain (domid_t)},
            hypercall_struct_field!{var xen_sysctl:u.getdomaininfolist.max_domains (uint32_t)},
            hypercall_struct_field!{typed_buf_wo_size xen_sysctl:u.getdomaininfolist.buffer (xen_domctl_getdomaininfo_t)},
            hypercall_struct_field!{var xen_sysctl:u.getdomaininfolist.num_domains (uint32_t)}
        }
}

hypercall! {xen_sysctl_debug_keys, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_debug_keys},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{buf_wo_size xen_sysctl:u.debug_keys.keys},
            hypercall_struct_field!{var xen_sysctl:u.debug_keys.nr_keys (uint32_t)}
        }
}

hypercall! {xen_sysctl_getcpuinfo, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_getcpuinfo},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.getcpuinfo.max_cpus (uint32_t)},
            hypercall_struct_field!{typed_buf_wo_size xen_sysctl:u.getcpuinfo.info (xen_sysctl_cpuinfo_t)},
            hypercall_struct_field!{var xen_sysctl:u.getcpuinfo.nr_cpus (uint32_t)}
        }
}

hypercall! {xen_sysctl_availheap, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_availheap},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.availheap.min_bitwidth (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.availheap.max_bitwidth (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.availheap.node (int32_t)},
            hypercall_struct_field!{var xen_sysctl:u.availheap.avail_bytes (uint64_t)}
        }
}

hypercall! {xen_sysctl_cpu_hotplug, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_cpu_hotplug},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.cpu_hotplug.cpu (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.cpu_hotplug.op (uint32_t)}
        }
}

hypercall! {xen_sysctl_page_offline_op, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_page_offline_op},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.page_offline.cmd (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.page_offline.start (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.page_offline.end (uint32_t)},
            hypercall_struct_field!{typed_buf_wo_size xen_sysctl:u.page_offline.status (u32)}
        }
}

hypercall! {xen_sysctl_lockprof_op, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_lockprof_op},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.lockprof_op.cmd (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.lockprof_op.max_elem (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.lockprof_op.nr_elem (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.lockprof_op.time (uint64_t)},
            hypercall_struct_field!{typed_buf_wo_size xen_sysctl:u.lockprof_op.data (xen_sysctl_lockprof_data_t)}
        }
}

hypercall! {xen_sysctl_cpupool_op, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_cpupool_op},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.cpupool_op.op (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.cpupool_op.cpupool_id (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.cpupool_op.sched_id (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.cpupool_op.domid (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.cpupool_op.cpu (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.cpupool_op.n_dom (uint32_t)},
            hypercall_struct_field!{buf_wo_size xen_sysctl:u.cpupool_op.cpumap.bitmap},
            hypercall_struct_field!{var xen_sysctl:u.cpupool_op.cpumap.nr_bits (uint32_t)}
        }
}

hypercall! {xen_sysctl_coverage_op, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_coverage_op},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.coverage_op.cmd (uint32_t)},
            hypercall_struct_field!{buf_with_size xen_sysctl:u.coverage_op.buffer => u.coverage_op.size}
        }
}

hypercall! {xen_sysctl_cpu_levelling_caps, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_get_cpu_levelling_caps},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.cpu_levelling_caps.caps (uint32_t)}
        }
}

hypercall! {xen_sysctl_cpu_featureset, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_get_cpu_featureset},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{var xen_sysctl:u.cpu_featureset.index (uint32_t)},
            hypercall_struct_field!{var xen_sysctl:u.cpu_featureset.nr_features (uint32_t)},
            hypercall_struct_field!{typed_buf_wo_size xen_sysctl:u.cpu_featureset.features (u32)}
        }
}

hypercall! {xen_sysctl_dt_overlay, __HYPERVISOR_sysctl,
        hypercall_arg!{0, complex_struct xen_sysctl,
            hypercall_struct_field!{const xen_sysctl:cmd (uint32_t) = XEN_SYSCTL_dt_overlay},
            hypercall_struct_field!{const xen_sysctl:interface_version (uint32_t) = XEN_SYSCTL_INTERFACE_VERSION},
            hypercall_struct_field!{buf_with_size xen_sysctl:u.dt_overlay.overlay_fdt => u.dt_overlay.overlay_fdt_size},
            hypercall_struct_field!{var xen_sysctl:u.dt_overlay.overlay_op (uint8_t)}
        }
}

pub fn generate_sysctl_op<S>(state: &mut S) -> GenericHypercallInput
where
    S: HasRand + HasMaxSize,
{
    // Safety: CTRS are nonempty
    GenericHypercallInput::new(state.rand_mut().choose(CTRS).unwrap()(), state)
}

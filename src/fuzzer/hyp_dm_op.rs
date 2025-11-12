use crate::fuzzer::generic_hypercall::*;

use crate::fuzzer::xen_bindings::*;
use crate::{hypercall, hypercall_arg, hypercall_struct_field};
use libafl::state::{HasMaxSize, HasRand};
use libafl_bolts::rands::Rand;
use paste::paste;
use std::mem::offset_of;

const CTRS: &'static [fn() -> GenericHypercallDef] = &[
    mk_xen_dmop_create_ioreq_server,
    mk_xen_dmop_get_ioreq_server_info,
    mk_xen_dmop_map_io_range_to_ioreq_server,
    mk_xen_dmop_unmap_io_range_from_ioreq_server,
    mk_xen_dmop_set_ioreq_server_state,
    mk_xen_dmop_destroy_ioreq_server,
    mk_xen_dmop_track_dirty_vram,
    mk_xen_dmop_set_pci_intx_level,
    mk_xen_dmop_set_isa_irq_level,
    mk_xen_dmop_set_irq_level,
    mk_xen_dmop_set_pci_link_route,
    mk_xen_dmop_modified_memory,
    mk_xen_dmop_set_mem_type,
    mk_xen_dmop_inject_event,
    mk_xen_dmop_inject_msi,
    mk_xen_dmop_map_mem_type_to_ioreq_server,
    mk_xen_dmop_remote_shutdown,
    mk_xen_dmop_relocate_memory,
    mk_xen_dmop_pin_memory_cacheattr,
    mk_xen_dmop_nr_vcpus,
];

hypercall! {xen_dmop_create_ioreq_server, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_create_ioreq_server},
               hypercall_struct_field!{enum xen_dm_op:u.create_ioreq_server.handle_bufioreq (uint8_t)[
                   HVM_IOREQSRV_BUFIOREQ_OFF as u8,
                   HVM_IOREQSRV_BUFIOREQ_LEGACY as u8,
                   HVM_IOREQSRV_BUFIOREQ_ATOMIC as u8,
                   0xFF]},
               hypercall_struct_field!{var xen_dm_op:u.create_ioreq_server.id (ioservid_t)}
            }
}

hypercall! {xen_dmop_get_ioreq_server_info, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_get_ioreq_server_info},
               hypercall_struct_field!{var xen_dm_op:u.get_ioreq_server_info.id (ioservid_t)},
               hypercall_struct_field!{enum xen_dm_op:u.get_ioreq_server_info.flags (uint16_t) [
                   0,
                   XEN_DMOP_no_gfns as u16,
                   0xFF]},
               hypercall_struct_field!{var xen_dm_op:u.get_ioreq_server_info.bufioreq_port (evtchn_port_t)},
               hypercall_struct_field!{var xen_dm_op:u.get_ioreq_server_info.ioreq_gfn (uint64_t)},
               hypercall_struct_field!{var xen_dm_op:u.get_ioreq_server_info.bufioreq_gfn (uint64_t)}
            }
}

hypercall! {xen_dmop_map_io_range_to_ioreq_server, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_map_io_range_to_ioreq_server},
               hypercall_struct_field!{var xen_dm_op:u.map_io_range_to_ioreq_server.id (ioservid_t)},
               hypercall_struct_field!{enum xen_dm_op:u.map_io_range_to_ioreq_server.type_ (uint32_t) [
                   XEN_DMOP_IO_RANGE_PORT,
                   XEN_DMOP_IO_RANGE_MEMORY,
                   XEN_DMOP_IO_RANGE_PCI,
                   XEN_DMOP_IO_RANGE_PCI + 1,
                   0xFF
               ]},
               hypercall_struct_field!{var xen_dm_op:u.map_io_range_to_ioreq_server.start (uint64_t)},
               hypercall_struct_field!{var xen_dm_op:u.map_io_range_to_ioreq_server.end (uint64_t)}
            }
}

hypercall! {xen_dmop_unmap_io_range_from_ioreq_server, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_unmap_io_range_from_ioreq_server},
               hypercall_struct_field!{var xen_dm_op:u.unmap_io_range_from_ioreq_server.id (ioservid_t)},
               hypercall_struct_field!{var xen_dm_op:u.unmap_io_range_from_ioreq_server.type_ (uint32_t)},
               hypercall_struct_field!{var xen_dm_op:u.unmap_io_range_from_ioreq_server.start (uint64_t)},
               hypercall_struct_field!{var xen_dm_op:u.unmap_io_range_from_ioreq_server.end (uint64_t)}
            }
}

hypercall! {xen_dmop_set_ioreq_server_state, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_set_ioreq_server_state},
               hypercall_struct_field!{var xen_dm_op:u.set_ioreq_server_state.id (ioservid_t)},
               hypercall_struct_field!{var xen_dm_op:u.set_ioreq_server_state.enabled (uint8_t)}
            }
}

hypercall! {xen_dmop_destroy_ioreq_server, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_destroy_ioreq_server},
               hypercall_struct_field!{var xen_dm_op:u.destroy_ioreq_server.id (ioservid_t)}
            }
}

hypercall! {xen_dmop_track_dirty_vram, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_track_dirty_vram},
               hypercall_struct_field!{var xen_dm_op:u.track_dirty_vram.nr (uint32_t)},
               hypercall_struct_field!{var xen_dm_op:u.track_dirty_vram.first_pfn (uint64_t)}
            }
}

hypercall! {xen_dmop_set_pci_intx_level, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_set_pci_intx_level},
               hypercall_struct_field!{var xen_dm_op:u.set_pci_intx_level.domain (uint16_t)},
               hypercall_struct_field!{var xen_dm_op:u.set_pci_intx_level.bus (uint8_t)},
               hypercall_struct_field!{var xen_dm_op:u.set_pci_intx_level.device (uint8_t)},
               hypercall_struct_field!{var xen_dm_op:u.set_pci_intx_level.intx (uint8_t)},
               hypercall_struct_field!{var xen_dm_op:u.set_pci_intx_level.level (uint8_t)}
            }
}

hypercall! {xen_dmop_set_isa_irq_level, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_set_isa_irq_level},
               hypercall_struct_field!{var xen_dm_op:u.set_isa_irq_level.isa_irq (uint8_t)},
               hypercall_struct_field!{var xen_dm_op:u.set_isa_irq_level.level (uint8_t)}
            }
}

hypercall! {xen_dmop_set_irq_level, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_set_irq_level},
               hypercall_struct_field!{var xen_dm_op:u.set_irq_level.irq (uint32_t)},
               hypercall_struct_field!{var xen_dm_op:u.set_irq_level.level (uint8_t)}
            }
}

hypercall! {xen_dmop_set_pci_link_route, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_set_pci_link_route},
               hypercall_struct_field!{var xen_dm_op:u.set_pci_link_route.link (uint8_t)},
               hypercall_struct_field!{var xen_dm_op:u.set_pci_link_route.isa_irq (uint8_t)}
            }
}

hypercall! {xen_dmop_modified_memory, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_modified_memory},
               hypercall_struct_field!{var xen_dm_op:u.modified_memory.nr_extents (uint32_t)},
               hypercall_struct_field!{var xen_dm_op:u.modified_memory.opaque (uint32_t)}
            }
}

hypercall! {xen_dmop_set_mem_type, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_set_mem_type},
               hypercall_struct_field!{var xen_dm_op:u.set_mem_type.nr (uint32_t)},
               hypercall_struct_field!{var xen_dm_op:u.set_mem_type.mem_type (uint16_t)},
               hypercall_struct_field!{var xen_dm_op:u.set_mem_type.first_pfn (uint64_t)}
            }
}

hypercall! {xen_dmop_inject_event, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_inject_event},
               hypercall_struct_field!{var xen_dm_op:u.inject_event.vcpuid (uint32_t)},
               hypercall_struct_field!{var xen_dm_op:u.inject_event.vector (uint8_t)},
               hypercall_struct_field!{enum xen_dm_op:u.inject_event.type_ (uint8_t) [
                   XEN_DMOP_EVENT_ext_int as u8,
                   XEN_DMOP_EVENT_nmi as u8,
                   XEN_DMOP_EVENT_hw_exc as u8,
                   XEN_DMOP_EVENT_sw_int as u8,
                   XEN_DMOP_EVENT_pri_sw_exc as u8,
                   XEN_DMOP_EVENT_sw_exc as u8,
                   XEN_DMOP_EVENT_pri_sw_exc as u8 + 1
               ]},
               hypercall_struct_field!{var xen_dm_op:u.inject_event.insn_len (uint8_t)},
               hypercall_struct_field!{var xen_dm_op:u.inject_event.error_code (uint32_t)},
               hypercall_struct_field!{var xen_dm_op:u.inject_event.cr2 (uint64_t)}
            }
}

hypercall! {xen_dmop_inject_msi, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_inject_msi},
               hypercall_struct_field!{var xen_dm_op:u.inject_msi.data (uint32_t)},
               hypercall_struct_field!{var xen_dm_op:u.inject_msi.addr (uint64_t)}
            }
}

hypercall! {xen_dmop_map_mem_type_to_ioreq_server, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_map_mem_type_to_ioreq_server},
               hypercall_struct_field!{var xen_dm_op:u.map_mem_type_to_ioreq_server.id (ioservid_t)},
               hypercall_struct_field!{enum xen_dm_op:u.map_mem_type_to_ioreq_server.type_ (uint16_t) [
                   hvmmem_type_t_HVMMEM_ram_rw as u16,
                   hvmmem_type_t_HVMMEM_ram_ro as u16,
                   hvmmem_type_t_HVMMEM_mmio_dm as u16,
                   hvmmem_type_t_HVMMEM_unused as u16,
                   hvmmem_type_t_HVMMEM_ioreq_server as u16
               ]},
               hypercall_struct_field!{enum xen_dm_op:u.map_mem_type_to_ioreq_server.flags (uint32_t) [
                   0,
                   XEN_DMOP_IOREQ_MEM_ACCESS_READ,
                   XEN_DMOP_IOREQ_MEM_ACCESS_WRITE,
                   XEN_DMOP_IOREQ_MEM_ACCESS_READ | XEN_DMOP_IOREQ_MEM_ACCESS_WRITE,
                   0xFF
               ]},
               hypercall_struct_field!{var xen_dm_op:u.map_mem_type_to_ioreq_server.opaque (uint64_t)}
            }
}

hypercall! {xen_dmop_remote_shutdown, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_remote_shutdown},
               hypercall_struct_field!{var xen_dm_op:u.remote_shutdown.reason (uint32_t)}
            }
}

hypercall! {xen_dmop_relocate_memory, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_relocate_memory},
               hypercall_struct_field!{var xen_dm_op:u.relocate_memory.size (uint32_t)},
               hypercall_struct_field!{var xen_dm_op:u.relocate_memory.src_gfn (uint64_t)},
               hypercall_struct_field!{var xen_dm_op:u.relocate_memory.dst_gfn (uint64_t)}
            }
}

hypercall! {xen_dmop_pin_memory_cacheattr, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_pin_memory_cacheattr},
               hypercall_struct_field!{var xen_dm_op:u.pin_memory_cacheattr.start (uint64_t)},
               hypercall_struct_field!{var xen_dm_op:u.pin_memory_cacheattr.end (uint64_t)},
               hypercall_struct_field!{enum xen_dm_op:u.pin_memory_cacheattr.type_ (uint32_t) [
                               XEN_DMOP_MEM_CACHEATTR_UC,
                               XEN_DMOP_MEM_CACHEATTR_WC,
                               XEN_DMOP_MEM_CACHEATTR_WT,
                               XEN_DMOP_MEM_CACHEATTR_WP,
                               XEN_DMOP_MEM_CACHEATTR_WB,
                               XEN_DMOP_MEM_CACHEATTR_UCM,
                               XEN_DMOP_MEM_CACHEATTR_UCM + 1
                           ]}
            }
}

hypercall! {xen_dmop_nr_vcpus, __HYPERVISOR_dm_op,
            hypercall_arg!{0, complex_struct xen_dm_op,
               hypercall_struct_field!{const xen_dm_op:op (uint32_t) = XEN_DMOP_nr_vcpus},
               hypercall_struct_field!{var xen_dm_op:u.nr_vcpus.vcpus (uint32_t)}
            }
}

pub fn generate_dm_op<S>(state: &mut S) -> GenericHypercallInput
where
    S: HasRand + HasMaxSize,
{
    // Safety: CTRS are nonempty
    GenericHypercallInput::new(state.rand_mut().choose(CTRS).unwrap()(), state)
}

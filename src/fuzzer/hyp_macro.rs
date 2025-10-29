/// Macros for generation hypercall definitions
// Idea is to write
// hypercall! {evtchn_bind_interdomain, __HYPERVISOR_event_channel_op,
//            {
//            hypercall_arg!(0, const EVTCHNOP_bind_interdomain),
//            hypercall_arg!(1, struct evtchn_bind_interdomain,
//                domid remote_dom,
//                evtchn remote_port,
//            })
// }
// Instead of
//
// fn mk_evtchn_bind_interdomain() -> GenericHypercallDef {
//     GenericHypercallDef {
//         id: __HYPERVISOR_event_channel_op,
//         args: vec![
//             HypercallArg::mk_const(0, EVTCHNOP_bind_interdomain),
//             HypercallArg::mk_buffer(
//                 1,
//                 size_of::<evtchn_bind_interdomain>(),
//                 vec![
//                     HypercallBufferField::mk_domid(offset_of!(evtchn_bind_interdomain, remote_dom)),
//                     HypercallBufferField::mk_evtchn_port(offset_of!(
//                         evtchn_bind_interdomain,
//                         remote_port
//                     )),
//                 ],
//             ),
//         ],
//     }
// }
// In other words, these two pieces of code must provide the same result

/// Will transorm
/// hypercall! (name, id, fields)
/// into
/// fn mk_{name} () -> GenericHypercallDef {
///     GenericHypercallDef {
///         id: {id},
///         args:  vec![{fields}]
///     }
/// }
///
#[macro_export]
macro_rules! hypercall {
    ($name:ident, $id:ident, $($fields:expr),+) => {
	paste! {
	    fn [<mk_ $name>] () -> GenericHypercallDef {
		GenericHypercallDef {
		    id: $id,
		    args: vec![$($fields),+]
		}
	    }
	}
    }
}

#[macro_export]
macro_rules! hypercall_arg {
    ($num:expr, const $val:expr) => {
	HypercallArg::mk_const($num, $val as u64)
    };

    ($num:expr, struct $name:ident, $($type:ident $field:ident),+) => {
	HypercallArg::mk_buffer($num, size_of::<$name>(), vec![
	    $(
		paste! {
		    HypercallBufferField::[<mk_ $type>] (offset_of!($name, $field))
		}
	    ),+
	])
    };

    ($num:expr, complex_struct $name:ident, $($fields:expr),+) => {
	HypercallArg::mk_buffer($num, size_of::<$name>(), vec![$($fields),+])
    };
}

#[macro_export]
macro_rules! hypercall_struct_field {
    (var $struct:ident : $($field:ident).+ ($type:ident))=>{
	paste! {
	    HypercallBufferField::[<mk_ $type>] (offset_of!($struct, $($field).+))
	}
    };

    (const $struct:ident : $($field:ident).+ ($type:ident) = $val:expr) => {
	paste! {
	    HypercallBufferField::[<mk_ $type _const>] (offset_of!($struct, $($field).+), $val)
	}
    };

    (buf_with_size $struct:ident : $($field:ident).+  => $($size_field:ident).+ ) => {
	HypercallBufferField::mk_buffer_with_size(offset_of!($struct, $($field).+),
						  offset_of!($struct, $($size_field).+))
    };
}

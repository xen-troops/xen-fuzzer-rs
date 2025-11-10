from clang.cindex import Index, CursorKind, TranslationUnit, Cursor, TokenKind
from pprint import pprint
from dataclasses import dataclass
from typing import List, Optional
from enum import Enum

KNOWN_HTPES = {"XEN_DOMCTL": ("domctl", "__HYPERVISOR_domctl")}

LEARNED_STRUCTS = []

HYP_DEFS = []

DOMCTL_OP_IDS = []

PASS = 0

MAIN_STRUCT: Cursor = None

CTORS = []


class FieldKind(Enum):
    CONST = 1
    VAR = 2
    BUF_WITH_SIZE = 3
    BUF_WO_SIZE = 4


@dataclass
class HypercallDef:
    hyp_id: str
    op: str
    struct_type: str
    fields: list


@dataclass
class HypercallField:
    ftype: str
    fname: str
    fkind: FieldKind
    fsize_name: Optional[str] = None


@dataclass
class DomctlOpStruct:
    node: Cursor


@dataclass
class DomctlMainStruct:
    node: Cursor
    ops: List[DomctlOpStruct]


def main():
    global out
    global PASS

    out = open("hyp_domctl.tmpl", "wt")
    index = Index.create()

    tu = index.parse("wrapper.h",
                     args=["--target=aarch64"],
                     options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
    if not tu:
        raise Exception("Can't parse")


#    pprint(get_info(tu.cursor))
    deep_dive(tu.cursor)
    ms = handle_main_struct(MAIN_STRUCT)
    PASS = 1
    deep_dive(tu.cursor)
    for op, struct, s in ms.ops:
        emit_hypercall_def(op, struct, s)
    emit_ctors(CTORS)
    print_structs(HYP_DEFS)
    print_ops(HYP_DEFS)


def get_info(node, depth=0):
    children = [get_info(c, depth + 1) for c in node.get_children()]
    return {
        "id": get_cursor_id(node),
        "kind": node.kind,
        "usr": node.get_usr(),
        "spelling": node.spelling,
        "location": node.location,
        "extent.start": node.extent.start,
        "extent.end": node.extent.end,
        "is_definition": node.is_definition(),
        "definition id": get_cursor_id(node.get_definition()),
        "children": children,
    }


def deep_dive(node):
    if node.kind == CursorKind.STRUCT_DECL:
        handle_struct(node)
    elif node.kind == CursorKind.MACRO_DEFINITION:
        handle_macro(node)
    for c in node.get_children():
        deep_dive(c)


def handle_macro(node: Cursor):
    if PASS == 0:
        return

    if node.extent.start in MAIN_STRUCT.extent:
        DOMCTL_OP_IDS.append(node.spelling)


def handle_struct(node):
    # if node.spelling not in LEARNED_STRUCTS:
    #     return
    global MAIN_STRUCT
    if node.spelling == "xen_domctl" and PASS == 0:
        print("Found main struct")
        #        pprint(get_info(node,1))
        MAIN_STRUCT = node
        return

    LEARNED_STRUCTS.append(DomctlOpStruct(node=node))


def find_struct(name: str) -> DomctlOpStruct:
    for x in LEARNED_STRUCTS:
        if x.node.spelling == name:
            return x
    return None


def handle_main_struct(node: Cursor):
    ops = []
    op_replacement = {
        "nodeaffinity":
        ["XEN_DOMCTL_getnodeaffinity", "XEN_DOMCTL_setnodeaffinity"],
        "vcpuaffinity":
        ["XEN_DOMCTL_getvcpuaffinity", "XEN_DOMCTL_setvcpuaffinity"],
        "vcpucontext":
        ["XEN_DOMCTL_getvcpucontext", "XEN_DOMCTL_setvcpucontext"],
        "tsc_info": ["XEN_DOMCTL_gettscinfo", "XEN_DOMCTL_settscinfo"],
        "hvmcontext": ["XEN_DOMCTL_gethvmcontext", "XEN_DOMCTL_sethvmcontext"],
        "hvmcontext_partial": ["XEN_DOMCTL_gethvmcontext_partial"],
        "address_size":
        ["XEN_DOMCTL_get_address_size", "XEN_DOMCTL_set_address_size"],
        "ext_vcpucontext":
        ["XEN_DOMCTL_get_ext_vcpucontext", "XEN_DOMCTL_set_ext_vcpucontext"],
        "gdbsx_guest_memio": ["XEN_DOMCTL_gdbsx_guestmemio"],
        # TODO: UnpauseVCPU as well
        "gdbsx_pauseunp_vcpu":
        ["XEN_DOMCTL_gdbsx_pausevcpu", "XEN_DOMCTL_gdbsx_unpausevcpu"],
        "vnuma": ["XEN_DOMCTL_setvnumainfo"],
        "paging_mempool": [
            "XEN_DOMCTL_get_paging_mempool_size",
            "XEN_DOMCTL_set_paging_mempool_size"
        ],
        "accesses_required": ["XEN_DOMCTL_set_access_required"],
    }

    for ch in node.get_children():
        if ch.kind == CursorKind.FIELD_DECL:
            print("Field", ch.spelling)
            if ch.spelling == "u":
                for u in ch.get_children().__next__().get_children():
                    struct = handle_main_union(u)
                    if struct:
                        if u.spelling in op_replacement.keys():
                            for op in op_replacement[u.spelling]:
                                ops.append((op, u.spelling, struct))
                            pass
                        else:
                            ops.append(("XEN_DOMCTL_" + u.spelling, u.spelling,
                                        struct))
    return DomctlMainStruct(node=node, ops=ops)


def handle_main_union(u):
    assert u.kind == CursorKind.FIELD_DECL

    fdec = list(u.get_children())
    assert len(fdec) == 1 or u.spelling == "pad"
    if u.spelling == "pad":
        return None

    op_struct_name = fdec[0].spelling.removeprefix("struct ")
    s = find_struct(op_struct_name)
    if s:
        return s
    else:
        raise Exception(f"Can't find struct for op {u.spelling}")


def get_cursor_id(cursor, cursor_list=[]):
    if not True:
        return None

    if cursor is None:
        return None

    # FIXME: This is really slow. It would be nice if the index API exposed
    # something that let us hash cursors.
    for i, c in enumerate(cursor_list):
        if cursor == c:
            return i
    cursor_list.append(cursor)
    return len(cursor_list) - 1


def emit_hypercall_def(op: str, sname: str, d: DomctlOpStruct):
    skips = [
        # inline struct
        "xen_domctl_createdomain",
        # enums
        "xen_domctl_scheduler_op",
        "xen_domctl_assign_device",
        "xen_domctl_bind_pt_irq",
        "xen_domctl_vm_event_op",
        "xen_domctl_mem_sharing_op",
        "xen_domctl_monitor_op"
    ]

    name = d.node.spelling.removeprefix("struct ")

    if name in skips:
        return

    fields = parse_fields(d)
    out.write(f"hypercall! {{{op.lower()}, __HYPERVISOR_domctl,\n")
    out.write("        hypercall_arg!{0, complex_struct xen_domctl,\n")
    out.write(
        f"            hypercall_struct_field!{{const xen_domctl:cmd (uint32_t) = {op}}},\n"
    )
    out.write(
        "            hypercall_struct_field!{const xen_domctl:interface_version (uint32_t) = XEN_DOMCTL_INTERFACE_VERSION},\n"
    )
    fields_str = [emit_hypercall_field(sname, f) for f in fields]
    out.write(",\n".join(fields_str) + "\n")
    out.write("        }\n")
    out.write("}\n")
    out.write("\n")

    CTORS.append(f"mk_{op.lower()}")


#    sys.exit(1)


def parse_fields(d: DomctlOpStruct) -> List[HypercallField]:
    ret: List[HypercallField] = []
    for ch in d.node.get_children():
        #        pprint(get_info(ch,1))
        array_len = None
        fname = ch.spelling
        if fname.startswith("pad") or fname.startswith("_"):
            continue
        if ch.kind != CursorKind.FIELD_DECL:
            pprint(get_info(ch, 0))
            raise Exception(f"Unexpected child kind {ch.kind}")
        field_def = list(ch.get_children())
        if field_def[0].kind == CursorKind.ALIGNED_ATTR:
            # Skip it
            del field_def[0]
        if len(field_def) > 1:
            if field_def[1].kind == CursorKind.INTEGER_LITERAL:
                tokens = list(field_def[1].get_tokens())
                if len(tokens) > 1 or tokens[0].kind != TokenKind.LITERAL:
                    raise Exception(
                        f"Don't know what to do with these tokens: {tokens}")
                array_len = int(tokens[0].spelling)
            else:
                raise Exception(f"More fields that expected: {get_info(ch)}")
        ftype = field_def[0].spelling
        fkind = FieldKind.VAR
        if ftype.startswith("__guest_handle_64_"):
            fkind = FieldKind.BUF_WO_SIZE
            ftype = ftype.removeprefix("__guest_handle_64_")
        elif ftype.startswith("struct "):
            # Great. We have embedded structure
            s = find_struct(ftype.removeprefix("struct "))
            if not s:
                raise Exception(f"Can't locate type {ftype}")


#            pprint(get_info(s.node))
            fields = parse_fields(s)
            for f in fields:
                f.fname = fname + "." + f.fname
                ret.append(f)

        if not ftype.startswith("struct ") and not array_len:
            ret.append(HypercallField(ftype=ftype, fname=fname, fkind=fkind))
        # if not array_len:
        #         ret.append(HypercallField(ftype=ftype, fname=fname, fkind=fkind))
        # else:
        #     for x in range(array_len):
        #         ret.append(HypercallField(ftype=ftype, fname=fname + f"__{x}", fkind=fkind))

    guess_buffers_with_size_var(ret)
    return ret


def guess_buffers_with_size_var(fields: List[HypercallField]):

    def try_field(fields: List[HypercallField], f: HypercallField, i: int):
        possible_names = ["count", "size", "overlay_fdt_size"]
        possible_types = ["uint32_t"]
        name = fields[i].fname.split(".")[-1]
        if name not in possible_names:
            return False
        t = fields[i].ftype
        if t not in possible_types:
            return False
        f.fkind = FieldKind.BUF_WITH_SIZE
        f.fsize_name = fields[i].fname
        del fields[i]

        return True

    for i, f in enumerate(fields):
        if f.fkind != FieldKind.BUF_WO_SIZE:
            continue
        res = False
        if i != len(fields) - 1:
            res = try_field(fields, f, i + 1)
        if not res and i != 0:
            try_field(fields, f, i - 1)


def emit_hypercall_field(struct_name: str, f: HypercallField):

    def fixup_fname(n: str):
        keywords = ["type"]
        parts = n.split(".")
        for i, p in enumerate(parts):
            if p in keywords:
                parts[i] = p + "_"
        return ".".join(parts)

    def fixup_type(t: str):
        fixups = {
            "uint32": "u32",
            "const_char": "char",
            "const_void": "char",
            "uint": "__u_int"
        }
        repl = fixups.get(t)
        if repl:
            return repl
        return t

    f.ftype = fixup_type(f.ftype)
    f.fname = fixup_fname(f.fname)
    fkind_str = "var"
    type_str = f" ({f.ftype})"
    fbufsize_str = ""
    if f.fkind == FieldKind.BUF_WO_SIZE:
        if f.ftype == "uint8_t" or f.ftype == "uint8" or f.ftype == "char":
            fkind_str = "buf_wo_size"
            type_str = ""
        else:
            fkind_str = "typed_buf_wo_size"
            if f.ftype == "uint32":
                type_str = " (u32)"
    elif f.fkind == FieldKind.BUF_WITH_SIZE:
        fbufsize_str = f" => u.{struct_name}.{f.fsize_name}"
        if f.ftype == "uint8_t" or f.ftype == "uint8" or f.ftype == "char":
            fkind_str = "buf_with_size"
            type_str = ""
        else:
            fkind_str = "typed_buf_with_size"
            if f.ftype == "uint32":
                type_str = " (u32)"

    return (
        " " * 12 +
        f"hypercall_struct_field!{{{fkind_str} xen_domctl:u.{struct_name}.{f.fname}{type_str}{fbufsize_str}}}"
    )


def emit_ctors(lst: List[str]):
    out.write("const CTRS: &'static [fn() -> GenericHypercallDef] = &[\n")
    for d in lst:
        out.write(f"    {d},\n")
    out.write("]")


def print_structs(lst: List[HypercallDef]):
    print("import structs:")
    for d in lst:
        print(f"{d.struct_type},")


def print_ops(lst: List[HypercallDef]):
    print("import ops:")
    for d in lst:
        print(f"{d.op},")


if __name__ == "__main__":
    main()

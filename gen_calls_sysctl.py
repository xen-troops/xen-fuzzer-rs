from clang.cindex import Index, CursorKind, TranslationUnit
from pprint import pprint
from dataclasses import dataclass
from typing import List
KNOWN_HTPES = {
    "EVTCHNOP": ("evtchn", "__HYPERVISOR_event_channel_op")
    }

LEARNED_STRUCTS = {
    }

HYP_DEFS = []

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

def main():
    global out
    out = open("hyp_sysctl.tmpl", "wt")
    index = Index.create()
    tu = index.parse("wrapper.h", args="", options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
    if not tu:
        raise Exception("Can't parse")
#    pprint(get_info(tu.cursor))
    deep_dive(tu.cursor)
    for d in HYP_DEFS:
        emit_hypercall_def(d)
    emit_ctors(HYP_DEFS)
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

def handle_macro(node):
    for k, v in KNOWN_HTPES.items():
        if node.spelling.startswith(k):
            LEARNED_STRUCTS[node.spelling.replace(k,v[0])] = (node.spelling, v)
            pprint(get_info(node, 1))

def handle_struct(node):
#    pprint(get_info(node))
    if node.spelling not in LEARNED_STRUCTS:
        return
    op = LEARNED_STRUCTS[node.spelling][0]
    hypercall_id = LEARNED_STRUCTS[node.spelling][1][1]
    fields = []
    print(f"struct {node.spelling}")
    for c in node.get_children():
        if c.kind == CursorKind.FIELD_DECL:
            if f:=handle_field(c):
                fields.append(f)
        elif c.kind == CursorKind.UNION_DECL:
            handle_union(node)
        else:
            print(f"unexpected kind: {c.kind}")
    d = HypercallDef(hypercall_id, op, node.spelling, fields)
    HYP_DEFS.append(d)

def handle_union(node):
    print("Skipping union for now")
    pass

def handle_union_field(node):
    print("Skipping union field for now")
    pass

def handle_field(node):
    t = None
    if node.spelling.startswith("_"):
        print(f"Skipping private field {node.spelling}")
        return
    for c in node.get_children():
        if c.kind == CursorKind.TYPE_REF:
            t = c.spelling
        elif c.kind == CursorKind.UNION_DECL:
            handle_union_field(node)
        else:
            print(f"   Unexpected field kind: {c.kind}")
#            pprint(get_info(c))
    print(f"  {t} {node.spelling}")
    if t:
        return HypercallField(t, node.spelling)
    return None

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

def emit_hypercall_def(d : HypercallDef) :
    out.write(f"hypercall! {{{d.struct_type}, {d.hyp_id},\n")
    out.write(f"        hypercall_arg!{{0, const {d.op}}},\n")
    out.write(f"        hypercall_arg!{{1, struct {d.struct_type},\n")
    fields = [emit_hypercall_field(f) for f in d.fields]
    out.write(",\n".join(fields) + "\n")
    out.write("        }\n")
    out.write("}\n")
    out.write("\n")

def emit_hypercall_field(f: HypercallField):
    return (" " * 16 + f"{f.ftype} {f.fname}")

def emit_ctors(lst: List[HypercallDef]):
    out.write("const CTRS: &'static [fn() -> GenericHypercallDef] = &[\n")
    for d in lst:
        out.write(f"    mk_{d.struct_type},\n")
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

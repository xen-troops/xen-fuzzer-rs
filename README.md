LibAFL-based Xen hypervisor fuzzer
==================================

Purpose
-------

This piece of software can be used to run fuzzing inside a QEMU. While
it is designed to fuzz Xen hypervisor, it can run other payloads as well.

Installation
------------

This software is written in Rust, so you need `cargo`, the Rust
package manager. Please consult your distributive documentation or
refer to
[Installation](https://doc.rust-lang.org/cargo/getting-started/installation.html)
section of The Cargo Book.

You will also might need "cargo make" module, which you can install with

```
 cargo install cargo-make
```

command. Just be sure that `~/.cargo/bin` is in your PATH
variable. You build Xen/XTF manually.

Clone this repository, and issue

```
 cargo build
```

command inside. This will build the fuzzer itself. You also can build a `master` branch of Xen with

```
 cargo make build_xen
```

You can override Xen Git URL with `XEN_URL` environment variable and
Xen Git revision with `XEN_REV`.

And XTF (which is used as test harness) with


```
 cargo make build_xtf
```

You can override XTF Git URL with `XTF_URL` environment variable and
XTF Git revision with `XTF_REV`.

Running the fuzzer
------------------

`xen_fuzzer` can be ran in two modes: fuzzing and replay.

### Fuzzer mode

#### Simple modes

Right now XTF supports two different fuzzing interfaces: `vgic` and `hypercall`.

If you built both Xen and XTF with `cargo make`, you can run `vgic` fuzzer simply by issuing

```
target/debug/xen_fuzzer vgic
```

The same for `hypercall` fuzzer:

```
target/debug/xen_fuzzer hypercall
```


This will run fuzzer in infinite loop mode. Exit from QEMU with `ctr-x a`
to end the fuzzing process.

Alternatively you can add `-t SECONDS` parameter to limit the running time:


```
target/debug/xen_fuzzer -t 60 vgic # Run vgic fuzzer for 60 seconds
```


Please note that this timeout is a lower limit, due to LibAFL
design. In fact, fuzzer can run longer, but it will stop eventually.

#### Custom mode

Often we want to run own custom Xen build or maybe use own
harness. This is possible with `run` mode:

```
target/debug/xen_fuzzer -t 120 run ~/work/xen/xen/xen target/xtf/tests/arm-hypercall-fuzzer/test-mmu64le-arm-hypercall-fuzzer
```

In this case we are running own Xen build which is located at
`~/work/xen/xen/xen` with default `hypercall` fuzzer for 120 seconds.

If you are building Xen manually - don't forget to configure
`CONFIG_LIBAFL_QEMU_FUZZER*` options.

#### Raw mode

Sometimes we might want to pass QEMU arguments directly (for example,
to reproduce a specific machine setup). This is possible with `raw` mode:

```
target/debug/xen_fuzzer raw -accel tcg \
  -machine virt,virtualization=yes,acpi=off,gic-version=2  -m 4G \
  -L  target/debug/qemu-libafl-bridge/pc-bios  \
  -nographic \
  -cpu max \
  -append 'dom0_mem=512M loglvl=all guest_loglvl=none console=dtuart' \
  -kernel ~/work/xen/xen/xen \
  -device guest-loader,addr=0x42000000,kernel=target/xtf/tests/arm-vgic-fuzzer/test-mmu64le-arm-vgic-fuzzer,bootargs="none" \
  -snapshot
```

Please note that `-snapshot` QEMU argument is required by fuzzer to function correctly.

### Replay mode

After successfully exit, fuzzer will tell you if to found any crashes:

```
Reached execution time limit. Exiting.
No objectives found, all good!
```

Or

```
Reached execution time limit. Exiting.
Found 12 objectives (crashes)
```

In this latter case it will also set return code to 1.

All crash inputs will be stored into `crashes/` directory. You can
replay any crash with `-r` parameter. For example, if you ran fuzzer
in custom mode:

```
target/debug/xen_fuzzer -t 120 run /path/to/xen /path/to/harness
```

Run it again with replay input provided:

```
target/debug/xen_fuzzer -r crashes/0195e4fc65828c17 run /path/to/xen /path/to/harness
```

This will help with debugging found crashes.

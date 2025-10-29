- Add possibility to chose GIC version via simplified interface
- Use structured input instead of raw byte arrays
- Investigate why `hypercall` fuzzer is so slow
- Implement multi-process fuzzing (LibAFL supports this, but it
  requires more complex code in fuzzer.rs)
- Add support for release builds
- Add possibility to randomize "size" fields for buffer arguments to feed invalid input to Xen

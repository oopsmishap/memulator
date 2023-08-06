# Memulator

A simple novel approach to memory only emulation, the main benifit of this approach is that it is very fast and can be 
used to emulate large programs with minimal overhead. However it is not a complete solution and will not work for all 
samples and is not intended to be a replacement for traditional emulation.

A good use case for this as can be seen in the examples is to emulate and extract xor encoded strings, this is a very
common anti-analysis technique.

This is a work in progress however the current implementation is functional with surprisingly good performance.

## How it works

You would first use [Capstone](https://github.com/capstone-engine/capstone) to disassemble the binary or regions you
wish to emulate as a list of instructions. Memulator will then emulate each instruction and track the memory state.

You are able to hook pre and post instructions with full Memulator context to perform additional analysis or logging.

```python
def collect_strings(cls: Memulator, inst: CsInsn):
    global strings
    tmp = cls.get_operand_value(inst.operands[0])
    string = tmp.to_bytes(inst.operands[0].size, 'little')
    strings.append((inst.address, string))


emu.add_post_instruction_hook('pxor', collect_strings)
```

See the [examples](examples) directory for further usage.

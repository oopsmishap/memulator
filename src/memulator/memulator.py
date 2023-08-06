import logging
from typing import List
from capstone import *
from capstone.x86 import *


logger = logging.getLogger("memulator")

class Stack:
    def __init__(self, stack_size=0x6000):
        self.stack_size = stack_size
        self.stack = bytearray(stack_size)
        self.stack_pointer = stack_size // 2
        self.stack_base = stack_size // 2

    def clear(self):
        self.stack = bytearray(self.stack_size)
        self.stack_pointer = self.stack_size // 2
        self.stack_base = self.stack_size // 2

    def save(self, value, offset: int, size: int, esp=False):
        assert size in (1, 2, 4, 8, 16, 32), f"Invalid size: {size}"

        if esp:
            logger.debug(f"Saving from {offset:x} + {self.stack_pointer:x}, "
                         f"({size:x} bytes) (esp={self._rel_stack_pointer():x})")
            offset = self.stack_pointer + offset
        else:
            logger.debug(f"Saving from {offset:x} + {self.stack_base:x}, "
                         f"({size:x} bytes) (esp={self._rel_stack_base():x})")
            offset = self.stack_base + offset

        # if offset is not in stack
        if offset < 0 or offset + size >= self.stack_size:
            return

        if size == 1:
            self.stack[offset] = value & 0xff
        elif size == 2:
            value = value & 0xffff
            self.stack[offset:offset + 2] = value.to_bytes(2, 'little')
        elif size == 4:
            value = value & 0xffffffff
            self.stack[offset:offset + 4] = value.to_bytes(4, 'little')
        elif size == 8:
            value = value & 0xffffffffffffffff
            self.stack[offset:offset + 8] = value.to_bytes(8, 'little')
        elif size == 16:
            value = value & 0xffffffffffffffffffffffffffffffff
            self.stack[offset:offset + 16] = value.to_bytes(16, 'little')
        elif size == 32:
            value = value & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            self.stack[offset:offset + 32] = value.to_bytes(32, 'little')
        else:
            raise Exception(f"Invalid size: {size}")

        # if logger level is DEBUG
        if logger.getEffectiveLevel() == logging.DEBUG:
            # hexdump stack +/- 0x30 bytes around stack pointer
            print_size = 0x20
            line_size = 0x4
            logger.debug(f"Saving {value:x} to {offset-self.stack_size//2:x} ({size:x} bytes) (esp={self._rel_stack_pointer():x})")
            for i in range(offset-print_size, offset+print_size, line_size):
                line = ""
                line += f"\t{i-self.stack_size//2:04x} "
                for j in range(line_size):
                    line += f"{self.stack[i+j]:02x}"
                if offset <= i < offset + size:
                    line += " <--"
                logger.debug(line)
            logger.debug("")

    def load(self, offset: int, size: int, esp=False):
        assert size in (1, 2, 4, 8, 16, 32), f"Invalid size: {size}"

        if esp:
            logger.debug(f"Loading from {offset:x} + {self.stack_pointer:x}, "
                         f"({size:x} bytes) (esp={self._rel_stack_pointer():x})")
            offset = self.stack_pointer + offset
        else:
            logger.debug(f"Loading from {offset:x} + {self.stack_base:x}, "
                         f"({size:x} bytes) (esp={self._rel_stack_base():x})")
            offset = self.stack_base + offset

        # if offset is not in stack
        if offset < 0 or offset >= self.stack_size:
            return 0
        if logger.getEffectiveLevel() == logging.DEBUG:
            print_size = 0x20
            line_size = 0x4
            logger.debug(f"Loading from {offset - self.stack_size // 2:x} ({size:x} bytes) "
                         f"(esp={self._rel_stack_pointer():x})")
            for i in range(offset - print_size, offset + print_size, line_size):
                line = ""
                line += f"\t{i - self.stack_size // 2:04x} "
                for j in range(line_size):
                    line += f"{self.stack[i + j]:02x}"
                if offset <= i < offset + size:
                    line += " <--"
                logger.debug(line)
            logger.debug("")

        if size == 1:
            return self.stack[offset]
        elif size == 2:
            return int.from_bytes(self.stack[offset:offset + 2], 'little')
        elif size == 4:
            return int.from_bytes(self.stack[offset:offset + 4], 'little')
        elif size == 8:
            return int.from_bytes(self.stack[offset:offset + 8], 'little')
        elif size == 16:
            return int.from_bytes(self.stack[offset:offset + 16], 'little')
        elif size == 32:
            return int.from_bytes(self.stack[offset:offset + 32], 'little')
        else:
            raise Exception(f"Invalid size: {size}")

    def adjust_stack(self, amount: int):
        self.stack_pointer += amount
        logger.debug(f"Adjusting stack pointer by {amount:x} to {self._rel_stack_pointer():x}")

    def adjust_base(self, amount: int):
        self.stack_base += amount
        logger.debug(f"Adjusting stack base by {amount:x} to {self._rel_stack_pointer():x}")

    def _rel_stack_pointer(self):
        return self.stack_pointer - self.stack_size//2

    def _rel_stack_base(self):
        return self.stack_base - self.stack_size//2

class Memulator:
    def __init__(self, stack_size=0x6000):
        self.stack = Stack(stack_size)
        self.reg = [0] * X86_REG_ENDING
        self.pre_hooks = {}
        self.post_hooks = {}
        self._ignore_next = False
        self._push_offset = 0

    def clear(self):
        self.stack.clear()
        self.reg = [0] * X86_REG_ENDING

    def ignore_next(self):
        self._ignore_next = True

    def emulate_instructions(self, instructions: List[CsInsn]):
        for instruction in instructions:
            logger.debug(f"0x{instruction.address:08x} {instruction.mnemonic} {instruction.op_str}")
            self._pre_instruction_hook(instruction)
            if self._ignore_next:
                self._ignore_next = False
                continue
            self._emulate_instruction(instruction)
            self._post_instruction_hook(instruction)
        self.clear()

    def _emulate_instruction(self, inst):
        if inst.mnemonic in ('mov', 'movaps', 'vmovdqu', 'vmovdqa', 'vmovaps',
                             'movups', 'movdqu', 'vmovdqa', 'movdqa'):
            self._emulate_mov(inst)
        elif inst.mnemonic in ('xor', 'pxor'):
            self._emulate_xor(inst)
        elif inst.mnemonic in ('vpxor', 'vpxord', 'vxorps'):
            self._emulate_vpxor(inst)
        elif inst.mnemonic == 'ret':
            self._emulate_ret()
        elif inst.mnemonic == 'push':
            self._emulate_push(inst)
        elif inst.mnemonic == 'pop':
            self._emulate_pop(inst)
        elif inst.mnemonic == 'add':
            self._emulate_add(inst)
        elif inst.mnemonic == 'sub':
            self._emulate_sub(inst)
        elif inst.mnemonic == 'call':
            self._emulate_call()
        else:
            raise Exception(f"Unsupported instruction: {inst.mnemonic}")

    def add_post_instruction_hook(self, key, hook):
        self.post_hooks[key] = hook

    def add_pre_instruction_hook(self, key, hook):
        self.pre_hooks[key] = hook

    def _pre_instruction_hook(self, inst: CsInsn):
        if inst.mnemonic in self.pre_hooks:
            self.pre_hooks[inst.mnemonic](self, inst)
        elif inst.address in self.pre_hooks:
            self.pre_hooks[inst.address](self, inst)

    def _post_instruction_hook(self, inst: CsInsn):
        if inst.mnemonic in self.post_hooks:
            self.post_hooks[inst.mnemonic](self, inst)
        elif inst.address in self.post_hooks:
            self.post_hooks[inst.address](self, inst)

    # mov    op1, op2
    # reads op2 and writes to op1
    def _emulate_mov(self, inst: CsInsn):
        assert len(inst.operands) == 2, f"Invalid number of operands in mov: {len(inst.operands)}"
        self.set_operand_value(inst.operands[0], self.get_operand_value(inst.operands[1]))

    # xor    op1, op2
    # reads op1, op2 and writes to op1
    def _emulate_xor(self, inst: CsInsn):
        assert len(inst.operands) == 2, f"Invalid number of operands in xor: {len(inst.operands)}"
        tmp1 = self.get_operand_value(inst.operands[0])
        tmp2 = self.get_operand_value(inst.operands[1])
        tmp3 = tmp1 ^ tmp2
        self.set_operand_value(inst.operands[0], tmp3)

    # vpxor   op1, op2, op3
    # reads op2, op3 and writes to op1
    def _emulate_vpxor(self, inst: CsInsn):
        assert len(inst.operands) == 3, f"Invalid number of operands in vpxor: {len(inst.operands)}"

        tmp1 = self.get_operand_value(inst.operands[1])
        tmp2 = self.get_operand_value(inst.operands[2])
        tmp3 = tmp1 ^ tmp2

        self.set_operand_value(inst.operands[0], tmp3)

    def _emulate_ret(self):
        self.clear()

    def _emulate_call(self):
        self.stack.adjust_stack(self._push_offset)
        self._push_offset = 0

    # push   op1
    # reads op1 and writes to stack pointer
    def _emulate_push(self, inst: CsInsn):
        assert len(inst.operands) == 1, f"Invalid number of operands in push: {len(inst.operands)}"
        self.stack.adjust_stack(-inst.operands[0].size)
        self._push_offset += inst.operands[0].size
        self.stack.save(self.get_operand_value(inst.operands[0]), 0, inst.operands[0].size)

    # pop    op1
    # reads stack and writes op1
    def _emulate_pop(self, inst: CsInsn):
        assert len(inst.operands) == 1, f"Invalid number of operands in pop: {len(inst.operands)}"
        if self._push_offset > 0:
            self.stack.adjust_stack(inst.operands[0].size)
            self._push_offset -= inst.operands[0].size
        self.stack.save(self.get_operand_value(inst.operands[0]), 0, inst.operands[0].size)

    # add    op1, op2
    # reads op1, op2 and writes op1
    def _emulate_add(self, inst: CsInsn):
        assert len(inst.operands) == 2, f"Invalid number of operands in add: {len(inst.operands)}"
        if inst.operands[0].reg == X86_REG_ESP:
            self.stack.adjust_stack(self.get_operand_value(inst.operands[1]))
        self.set_operand_value(
            inst.operands[0],
            self.get_operand_value(inst.operands[0]) + self.get_operand_value(inst.operands[1])
        )

    # sub    op1, op2
    # reads op1, op2 and writes op1
    def _emulate_sub(self, inst: CsInsn):
        assert len(inst.operands) == 2, f"Invalid number of operands in sub: {len(inst.operands)}"
        if inst.operands[0].reg == X86_REG_ESP:
            self.stack.adjust_stack(-self.get_operand_value(inst.operands[1]))
        self.set_operand_value(
            inst.operands[0],
            self.get_operand_value(inst.operands[0]) - self.get_operand_value(inst.operands[1])
        )

    @staticmethod
    def is_mem_access_stack_pointer(operand: X86Op):
        return operand.mem.base in (X86_REG_ESP, X86_REG_RSP)

    @staticmethod
    def is_mem_access_base_pointer(operand: X86Op):
        return operand.mem.base in (X86_REG_EBP, X86_REG_RBP)

    def get_operand_value(self, operand: X86Op, size=None):
        if size is None:
            size = operand.size
        if operand.type == X86_OP_REG:
            return self.reg[operand.reg]
        elif operand.type == X86_OP_IMM:
            return operand.imm
        elif operand.type == X86_OP_MEM:
            if self.is_mem_access_stack_pointer(operand):
                return self.stack.load(operand.mem.disp, operand.size, True)
            elif self.is_mem_access_base_pointer(operand):
                return self.stack.load(operand.mem.disp, operand.size, False)
            else:
                # TODO: handle and track memory accesses
                return -1
        else:
            raise Exception(f"Invalid operand type: {operand.type}")

    def set_operand_value(self, operand: X86Op, value, size=None):
        if size is None:
            size = operand.size
        if operand.type == X86_OP_REG:
            self.reg[operand.reg] = value
        elif operand.type == X86_OP_MEM:
            if self.is_mem_access_stack_pointer(operand):
                self.stack.save(value, operand.mem.disp, size, True)
            elif self.is_mem_access_base_pointer(operand):
                self.stack.save(value, operand.mem.disp, size, False)
            else:
                # TODO: handle and track memory accesses
                return -1
        else:
            raise Exception(f"Invalid operand type: {operand.type}")
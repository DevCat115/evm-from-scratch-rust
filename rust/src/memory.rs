use primitive_types::U256;

use crate::STACK_LIMIT;

/*
 * The Memory
 *
 * EVM memory is not persistent and is destroyed at the end of the call context.
 * At the start of a call context, memory is initialized to 0.
 * Reading and Writing from memory is usually done with MLOAD and MSTORE instructions respectively, but can also be accessed by other instructions like CREATE or EXTCODECOPY.
 * https://www.evm.codes/about#memory
 *
 *
 * Memory Expansion
 *
 * During a smart contract execution, memory can be accessed with opcodes.
 * When an offset is first accessed (either read or write), memory may trigger an expansion, which costs gas.
 *
 * Memory expansion may be triggered when the byte offset (modulo 32) accessed is bigger than previous offsets.
 * If a larger offset trigger of memory expansion occurs, the cost of accessing the higher offset is computed and removed from the total gas available at the current call context.
 *
 * The total cost for a given memory size is computed as follows:
 *      memory_size_word = (memory_byte_size + 31) / 32
 *      memory_cost = (memory_size_word ** 2) / 512 + (3 * memory_size_word)
 *
 * When a memory expansion is triggered, only the additional bytes of memory must be paid for.
 * Therefore, the cost of memory expansion for the specific opcode is thus:
 *      memory_expansion_cost = new_memory_cost - last_memory_cost
 *
 * The memory_byte_size can be obtained with opcode MSIZE.
 * The cost of memory expansion triggered by MSIZE grows quadratically, disincentivizing the overuse of memory by making higher offsets more costly.
 * Any opcode that accesses memory may trigger an expansion (such as MLOAD, RETURN or CALLDATACOPY).
 * Note that opcodes with a byte size parameter of 0 will not trigger memory expansion, regardless of their offset parameters.
 * https://www.evm.codes/about#memoryexpansion
 */
pub struct Memory {
    data: Vec<u8>,
    size: u32,
}

impl Memory {
    pub fn new() -> Memory {
        Memory {
            data: vec![0; STACK_LIMIT * STACK_LIMIT], // this creates a fixed vector with all zeros
            size: 0,
        }
    }

    pub fn store(&mut self, offset: usize, value: U256) {
        for i in 0..32 {
            self.data[offset + i] =
                ((value >> ((32 - i - 1) * 8)) & U256::from(0xff)).low_u64() as u8;
        }

        self.size = std::cmp::max(self.size, (offset + 32) as u32);
    }

    pub fn store_u8(&mut self, offset: usize, value: u8) {
        self.data[offset] = value;

        self.size = std::cmp::max(self.size, (offset + 1) as u32);
    }

    pub fn load(&mut self, offset: usize, size: usize) -> U256 {
        // Expand memory with uint256(0) to the offset position if necessary.
        let limit_32 = if (offset + 32) % 32 != 0 {
            (((offset + 32) / 32) + 1) * 32
        } else {
            ((offset + 32) / 32) * 32
        };

        self.size = std::cmp::max(self.size, limit_32 as u32);

        let mut value = U256::zero();
        for i in 0..size {
            value = (value << 8) | U256::from(self.data[offset + i]);
        }
        value
    }

    pub fn size(&self) -> u32 {
        self.size
    }
}

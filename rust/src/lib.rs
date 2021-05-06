mod memory;
mod opcodes;
mod utils;

use opcodes::Opcode;
//use utils::pop;
use alloy::primitives::keccak256;
use primitive_types::U256;
use serde::Deserialize;

const STACK_LIMIT: usize = 1024;

pub struct EvmResult {
    pub stack: Vec<U256>,
    pub success: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct TxData {
    to: Option<String>,
    from: Option<String>,
    origin: Option<String>,
    gasprice: Option<String>,
    value: Option<String>,
    data: Option<String>,
}

pub fn evm(_code: impl AsRef<[u8]>, tx: &TxData) -> EvmResult {
    /*
     * The Stack
     *
     * The stack is a list of 32-byte elements used to store smart contract instruction inputs and outputs.
     * There is one stack created per call context, and it is destroyed when the call context ends.
     * When a new value is put on the stack, it is put on top, and only the top values are used by the instructions.
     * The stack currently has a maximum limit of 1024 values.
     * All instructions interact with the stack, but it can be directly manipulated with instructions like PUSH1, POP, DUP1, or SWAP1.
     * https://www.evm.codes/about#stack
     */
    let mut stack: Vec<U256> = Vec::with_capacity(STACK_LIMIT);

    /*
     * The Program Counter (PC)
     *
     * The Program Counter (PC) encodes which instruction, stored in the code, should be next read by the EVM.
     * The program counter is usually incremented by one byte, to point to the following instruction, with some exceptions.
     * For instance, the PUSHx instruction is longer than a single byte, and causes the PC to skip their parameter.
     * The JUMP instruction does not increase the PC's value, instead, it modifies the program counter to a position specified by the top of the stack.
     * JUMPI does this as well, if its condition is true (a nonzero code value), otherwise, it increments the PC like other instructions.
     * https://www.evm.codes/about#counter
     */
    let mut pc = 0;

    /*
     * The Code
     *
     * The code is the region where instructions are stored.
     * Instruction data stored in the code is persistent as part of a contract account state field.
     * Externally owned accounts (or EOAs) have empty code regions.
     * Code is the bytes read, interpreted, and executed by the EVM during smart contract execution.
     * Code is immutable, which means it cannot be modified, but it can be read with the instructions CODESIZE and CODECOPY.
     * The code of one contract can be read by other contracts, with instructions EXTCODESIZE and EXTCODECOPY.
     * https://www.evm.codes/about#code
     *
     *
     * Example EVM sequence:
     * PUSH1 0x01 PUSH1 0x02 POP
     *
     * Associated bytecode:
     * 0x60016002050
     *
     * How code actually looks like here in Rust:
     * [96, 1, 96, 2, 80]
     */
    let code = _code.as_ref();

    let mut memory = memory::Memory::new();

    while pc < code.len() {
        let opcode = code[pc];
        pc += 1;

        if opcode == Opcode::STOP.value() {
            // STOP
            break;
        }

        if opcode == Opcode::ADD.value() {
            // let element1 = utils::pop(&mut stack).unwrap();
            // let element2 = utils::pop(&mut stack).unwrap();

            // let element1 = match utils::pop(&mut stack) {
            //     Some(element) => element,
            //     None => {
            //         panic!("Failed to pop element from stack");
            //     }
            // };

            // let element2 = match utils::pop(&mut stack) {
            //     Some(element) => element,
            //     None => {
            //         panic!("Failed to pop element from stack");
            //     }
            // };

            let element1 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from stack");

            let (sum, _is_overflowed) = element1.overflowing_add(element2);
            utils::push(&mut stack, sum);
        }

        if opcode == 0x02 {
            // MUL
            let element1 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from stack");

            let (mul, _is_overflowed) = element1.overflowing_mul(element2);

            utils::push(&mut stack, mul);
        }

        if opcode == 0x03 {
            // SUB
            let element1 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from stack");

            let (sub, _is_overflowed) = element1.overflowing_sub(element2);

            utils::push(&mut stack, sub);
        }

        if opcode == 0x04 {
            // DIV
            let element1 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from stack");

            // This crashes the entire test
            //
            // if element2 == U256::from(0) {
            //
            // } else {
            //     let div = element1 / element2;
            //     stack.insert(0, div);
            // }

            // This panics as well
            //
            // match element1.checked_div(element2) {
            //     Some(div) => stack.insert(0, div),
            //     None => {
            //         panic!("Division by zero");
            //     }
            // };

            let div = element1.checked_div(element2).unwrap_or_default();

            utils::push(&mut stack, div);
        }

        if opcode == 0x05 {
            // SDIV
            let mut element1 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let mut element2 = utils::pop(&mut stack).expect("Failed to pop element from stack");

            // All values are treated as two’s complement signed 256-bit integers. Note the overflow semantic when −2^255 is negated.
            // returns integer result of the signed integer division. If the denominator is 0, the result will be 0.

            let element1_sign: i32;
            let element2_sign: i32;

            if !element1.bit(255) {
                element1_sign = if element1.is_zero() { 0 } else { 1 };
            } else {
                element1_sign = -1;
                element1 = (!element1) + 1; // bitwise flip and add 1
            }

            if !element2.bit(255) {
                element2_sign = if element2.is_zero() { 0 } else { 1 };
            } else {
                element2_sign = -1;
                element2 = (!element2) + 1; // bitwise flip and add 1
            }

            let mut div = element1.checked_div(element2).unwrap_or_default();
            if element1_sign * element2_sign == -1 {
                div = !div + 1;
            }

            utils::push(&mut stack, div);
        }

        if opcode == 0x06 {
            // MOD
            let element1 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from stack");

            // checked_rem is a safe version of % operator
            let modulo = element1.checked_rem(element2).unwrap_or_default();
            utils::push(&mut stack, modulo);
        }

        if opcode == 0x07 {
            // SMOD
            let mut element1 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from stack");

            let element1_sign = if !element1.bit(255) {
                if element1.is_zero() {
                    0
                } else {
                    1
                }
            } else {
                element1 = (!element1).overflowing_add(U256::one()).0;
                -1
            };

            let element2_abs = if element2.bit(255) {
                (!element2).overflowing_add(U256::one()).0
            } else {
                element2
            };

            let mut res = element1.checked_rem(element2_abs).unwrap_or_default();
            if element1_sign == -1 {
                res = (!res).overflowing_add(U256::one()).0;
            }

            utils::push(&mut stack, res);
        }

        if opcode == 0x08 {
            // ADDMOD, (a + b) % c
            let element1 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let element3 = utils::pop(&mut stack).expect("Failed to pop element from stack");

            let (sum, _is_overflowed) = element1.overflowing_add(element2);
            let res = sum.checked_rem(element3).unwrap_or_default();

            utils::push(&mut stack, res);
        }

        if opcode == 0x09 {
            // MULMOD
            let element1 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let element3 = utils::pop(&mut stack).expect("Failed to pop element from stack");

            // let (mul, _is_overflowed) = element1.overflowing_mul(element2);
            // let res = mul.checked_rem(element3).unwrap_or_default();
            // utils::push(&mut stack, res);

            let element1_mod = element1.checked_rem(element3).unwrap_or_default();
            let element2_mod = element2.checked_rem(element3).unwrap_or_default();
            let res = element1_mod.checked_mul(element2_mod).unwrap_or_default();

            utils::push(&mut stack, res);
        }

        if opcode == 0x0A {
            // EXP
            let element1 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from stack");

            let exp = element1.pow(element2);

            utils::push(&mut stack, exp);
        }

        if opcode == 0x0B {
            // SIGNEXTEND
            // Extend length of two’s complement signed integer
            let size = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let value = utils::pop(&mut stack).expect("Failed to pop element from stack");

            if size < U256::from(32) {
                let bit_index = (8 * size.as_usize() + 7) as usize;
                let bit = value.bit(bit_index);
                let mask = (U256::from(1) << bit_index) - U256::from(1);
                let result = if bit { value | !mask } else { value & mask };

                utils::push(&mut stack, result);
            }
        }

        if opcode == 0x10 {
            // LT
            let element1 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from stack");

            let result = if element1 < element2 {
                U256::one()
            } else {
                U256::zero()
            };

            utils::push(&mut stack, result);
        }

        if opcode == 0x11 {
            // GT
            let element1 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from stack");

            let result = if element1 > element2 {
                U256::one()
            } else {
                U256::zero()
            };

            utils::push(&mut stack, result);
        }

        if opcode == 0x12 {
            // SLT
            let element1 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from stack");

            let element1_sign = if !element1.bit(255) {
                if element1.is_zero() {
                    0
                } else {
                    1
                }
            } else {
                -1
            };

            let element2_sign = if !element2.bit(255) {
                if element2.is_zero() {
                    0
                } else {
                    1
                }
            } else {
                -1
            };

            let result = if element1_sign < element2_sign {
                U256::one()
            } else {
                U256::zero()
            };

            utils::push(&mut stack, result);
        }

        if opcode == 0x13 {
            // SGT
            let mut element1 = utils::pop(&mut stack).expect("Failed to pop element from stack");
            let mut element2 = utils::pop(&mut stack).expect("Failed to pop element from stack");

            let element1_sign = if !element1.bit(255) {
                if element1.is_zero() {
                    0
                } else {
                    1
                }
            } else {
                element1 = (!element1).overflowing_add(U256::one()).0;
                -1
            };

            let element2_sign = if !element2.bit(255) {
                if element2.is_zero() {
                    0
                } else {
                    1
                }
            } else {
                element2 = (!element2).overflowing_add(U256::one()).0; // The overflowing_add function returns a tuple where the first element is the result of the addition and the second element is a boolean that indicates whether an arithmetic overflow occurred. 0 means the first element of the tupple
                -1
            };

            let result = if element1_sign > element2_sign {
                U256::one()
            } else if element1_sign < element2_sign {
                U256::zero()
            } else {
                if element1_sign == -1 {
                    if element1 < element2 {
                        U256::one()
                    } else {
                        U256::zero()
                    }
                } else {
                    if element1 > element2 {
                        U256::one()
                    } else {
                        U256::zero()
                    }
                }
            };

            utils::push(&mut stack, result);
        }

        if opcode == 0x14 {
            // EQ
            let element1 = utils::pop(&mut stack).expect("Failed to pop element from the stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from the stack");

            let res = if element1 == element2 {
                U256::one()
            } else {
                U256::zero()
            };

            utils::push(&mut stack, res);
        }

        if opcode == 0x15 {
            // ISZERO
            let element = utils::pop(&mut stack).expect("Failed to pop element from the stack");

            let res = if element == U256::zero() {
                U256::one()
            } else {
                U256::zero()
            };

            utils::push(&mut stack, res);
        }

        if opcode == 0x16 {
            // AND
            let element1 = utils::pop(&mut stack).expect("Failed to pop element from the stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from the stack");

            // let res = if element1 & element2 {U256::max_value()} else {U256::zero()};
            let res = element1 & element2;

            utils::push(&mut stack, res);
        }

        if opcode == 0x17 {
            // OR
            let element1 = utils::pop(&mut stack).expect("Failed to pop element from the stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from the stack");

            let res = element1 | element2;

            utils::push(&mut stack, res);
        }

        if opcode == 0x18 {
            // XOR
            let element1 = utils::pop(&mut stack).expect("Failed to pop element from the stack");
            let element2 = utils::pop(&mut stack).expect("Failed to pop element from the stack");

            let res = element1 ^ element2;

            utils::push(&mut stack, res);
        }

        if opcode == 0x19 {
            // NOT
            let element = utils::pop(&mut stack).expect("Failed to pop element from the stack");

            let res = !element;

            utils::push(&mut stack, res);
        }

        if opcode == 0x1A {
            // BYTE
            // Retrieve a single byte from word
            let byte_offset = utils::pop(&mut stack).expect("Failed to pop element from the stack");
            let word_value = utils::pop(&mut stack).expect("Failed to pop element from the stack");

            let res = if byte_offset < U256::from(32) {
                let byte_index = 31 - byte_offset.as_usize();
                let byte = (word_value >> (byte_index * 8)) & U256::from(0xff);
                byte
            } else {
                U256::zero()
            };

            utils::push(&mut stack, res);
        }

        if opcode == 0x1B {
            // SHL
            let shift = utils::pop(&mut stack).expect("Failed to pop element from the stack");
            let value = utils::pop(&mut stack).expect("Failed to pop element from the stack");

            let res = value << shift;

            utils::push(&mut stack, res);
        }

        if opcode == 0x1C {
            // SHR
            let shift = utils::pop(&mut stack).expect("Failed to pop element from the stack");
            let value = utils::pop(&mut stack).expect("Failed to pop element from the stack");

            let res = value >> shift;

            utils::push(&mut stack, res);
        }

        if opcode == 0x1D {
            // SAR
            let shift = utils::pop(&mut stack).expect("Failed to pop element from the stack");
            let value = utils::pop(&mut stack).expect("Failed to pop element from the stack");

            let res = if shift >= U256::from(256) {
                if !value.bit(255) {
                    U256::zero()
                } else {
                    U256::max_value()
                }
            } else if !value.bit(255) {
                value >> shift
            } else {
                let mask = U256::max_value() << (U256::from(256) - shift);
                (value >> shift) | mask
            };

            utils::push(&mut stack, res);
        }

        if opcode == Opcode::KECCAK256.value() {
            // offset: byte offset in the memory.
            // size: byte size to read in the memory.
            let offset = utils::pop(&mut stack).expect("Failed to pop element from the stack");
            let size = utils::pop(&mut stack).expect("Failed to pop element from the stack");

            let to_hash = memory.load(offset.as_usize(), size.as_usize());

            let mut bytes_array = [0u8; 32];
            to_hash.to_big_endian(&mut bytes_array);

            let nonzero_bytes_array =
                &bytes_array[bytes_array.iter().position(|&x| x != 0).unwrap()..];

            let hash = keccak256(nonzero_bytes_array);
            utils::push(&mut stack, U256::from_big_endian(hash.as_slice()));
        }

        // if opcode == Opcode::ADDRESS.value() {
        //     let msg_sender = &tx.clone().to.expect("Transaction field to not set");
        //     utils::push(&mut stack, U256::from_big_endian(msg_sender.as_bytes()));
        // }

        if opcode == Opcode::ADDRESS.value() {
            let tx_to = match &tx.to {
                Some(to) => to,
                None => {
                    return EvmResult {
                        stack: stack,
                        success: false,
                    }
                }
            };

            let tx_to = tx_to.trim_start_matches("0x");
            let to = hex::decode(tx_to).expect("Decoding failed");

            utils::push(&mut stack, U256::from(to.as_slice()));
        }

        if opcode == Opcode::CALLER.value() {
            let tx_from = match &tx.from {
                Some(from) => from,
                None => {
                    return EvmResult {
                        stack: stack,
                        success: false,
                    }
                }
            };

            let tx_from = tx_from.trim_start_matches("0x");
            let msg_sender = hex::decode(tx_from).expect("Decoding failed");

            utils::push(&mut stack, U256::from(msg_sender.as_slice()));
        }

        if opcode == Opcode::ORIGIN.value() {
            let tx_origin = match &tx.origin {
                Some(origin) => origin,
                None => {
                    return EvmResult {
                        stack: stack,
                        success: false,
                    }
                }
            };

            let tx_origin = tx_origin.trim_start_matches("0x");
            let tx_origin_decoded = hex::decode(tx_origin).expect("Decoding failed");

            utils::push(&mut stack, U256::from(tx_origin_decoded.as_slice()));
        }

        if opcode == Opcode::GASPRICE.value() {
            let tx_gasprice = match &tx.gasprice {
                Some(gasprice) => gasprice,
                None => {
                    return EvmResult {
                        stack: stack,
                        success: false,
                    }
                }
            };

            let tx_gasprice = tx_gasprice.trim_start_matches("0x");
            let gasprice = hex::decode(tx_gasprice).expect("Decoding failed");

            utils::push(&mut stack, U256::from(gasprice.as_slice()));
        }

        if opcode == Opcode::COINBASE.value() {
            // Pull this from Block
        }

        if opcode == Opcode::BASEFEE.value() {
            // Pull this from Block
        }

        if opcode == Opcode::POP.value() {
            utils::pop(&mut stack);
        }

        if opcode == Opcode::MLOAD.value() {
            // offset: offset in the memory in bytes.
            let offset = utils::pop(&mut stack).expect("Failed to pop element from the stack");

            let value = memory.load(offset.as_usize(), 32);

            utils::push(&mut stack, value);
        }

        if opcode == Opcode::MSTORE.value() {
            // offset: offset in the memory in bytes.
            // value: 32-byte value to write in the memory.

            let offset = utils::pop(&mut stack).expect("Failed to pop element from the stack");
            let value = utils::pop(&mut stack).expect("Failed to pop element from the stack");

            memory.store(offset.as_usize(), value);
        }

        if opcode == Opcode::MSTORE8.value() {
            // offset: offset in the memory in bytes.
            // value: 1-byte value to write in the memory (the least significant byte of the 32-byte stack value).

            let offset = utils::pop(&mut stack).expect("Failed to pop element from the stack");
            let value = utils::pop(&mut stack)
                .expect("Failed to pop element from the stack")
                .low_u32() as u8;

            memory.store_u8(offset.as_usize(), value);
        }

        if opcode == Opcode::JUMP.value() {
            // counter - byte offset in the deployed code where execution will continue from. Must be a JUMPDEST instruction.
            let counter = utils::pop(&mut stack)
                .expect("Failed to pop element from the stack")
                .as_usize();

            // The `is_invalid_jumpdest` condition checks Ethereum Yellow Paper 9.4.3. Jump Destination Validity section:
            // All such positions must be on valid instruction boundaries, rather than sitting in the data portion of PUSH
            // operations and must appear within the explicitly defined portion of the code
            // (rather than in the implicitly defined STOP operations that trail it)

            let is_jumpdest = code[counter] == Opcode::JUMPDEST.value();
            let is_invalid_jumpdest = code[counter - 1] >= Opcode::PUSH1.value()
                && code[counter - 1] <= Opcode::PUSH32.value();

            if !is_jumpdest || is_invalid_jumpdest {
                return EvmResult {
                    stack: stack,
                    success: false,
                };
            }

            pc = counter;
        }

        if opcode == Opcode::JUMPI.value() {
            // counter: byte offset in the deployed code where execution will continue from. Must be a JUMPDEST instruction.
            // b: the program counter will be altered with the new value only if this value is different from 0. Otherwise, the program counter is simply incremented and the next instruction will be executed.
            let counter = utils::pop(&mut stack)
                .expect("Failed to pop element from the stack")
                .as_usize();

            let b = utils::pop(&mut stack).expect("Failed to pop element from the stack");

            if b != U256::zero() {
                let is_jumpdest = code[counter] == Opcode::JUMPDEST.value();
                let is_invalid_jumpdest = code[counter - 1] >= Opcode::PUSH1.value()
                    && code[counter - 1] <= Opcode::PUSH32.value();

                if !is_jumpdest || is_invalid_jumpdest {
                    return EvmResult {
                        stack: stack,
                        success: false,
                    };
                }

                pc = counter;
            }
        }

        if opcode == Opcode::PC.value() {
            utils::push(&mut stack, U256::from(pc - 1));
        }

        if opcode == Opcode::MSIZE.value() {
            utils::push(&mut stack, U256::from(memory.size()));
        }

        if opcode == Opcode::GAS.value() {
            utils::push(&mut stack, U256::max_value());
        }

        if opcode == Opcode::JUMPDEST.value() {
            // JUMPDEST
        }

        if opcode == Opcode::PUSH0.value() {
            utils::push(&mut stack, U256::from(0));
        }

        if opcode >= Opcode::PUSH1.value() && opcode <= Opcode::PUSH32.value() {
            let push_len = (opcode - 0x5f) as usize;
            // push adds element to the end
            // insert adds element to the specified index
            // these tests expect the top of the stack to be the first element
            // stack.insert(0, U256::from(&code[pc..pc+push_len]));
            utils::push(&mut stack, U256::from(&code[pc..pc + push_len]));
            pc += push_len;
        }

        if opcode >= Opcode::DUP1.value() && opcode <= Opcode::DUP16.value() {
            let n = (opcode - 0x7f) as usize;
            let element = stack
                .get(n - 1)
                .expect("Failed to get element from stack")
                .clone();

            utils::push(&mut stack, element);
        }

        if opcode >= Opcode::SWAP1.value() && opcode <= Opcode::SWAP16.value() {
            let n = (opcode - 0x8f) as usize;
            if n < stack.len() {
                stack.swap(0, n);
            } else {
                panic!("Stack underflow");
            }
        }

        if opcode == 0xfe {
            // INVALID
            return EvmResult {
                stack: stack,
                success: false,
            };
        }

        // panic!("HALT: Unknown opcode");
    }

    // TODO: Implement me

    return EvmResult {
        stack: stack,
        success: true,
    };
}

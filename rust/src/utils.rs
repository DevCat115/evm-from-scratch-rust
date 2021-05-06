use crate::STACK_LIMIT;
use primitive_types::U256;

pub fn push(stack: &mut Vec<U256>, element: U256) {
    if stack.len() == STACK_LIMIT {
        panic!("Stack overflow!");
    }

    stack.insert(0, element);
}

pub fn pop(stack: &mut Vec<U256>) -> Option<U256> {
    if !stack.is_empty() {
        Some(stack.remove(0))
    } else {
        // what if stack is empty?
        None
    }
}

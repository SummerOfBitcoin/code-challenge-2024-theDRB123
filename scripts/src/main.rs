#![allow(warnings)]
mod block_maker;
mod serialization;
mod test_functions;
mod validation;

fn main() {
    println!("Block Maker");
    block_maker::block_maker();
}



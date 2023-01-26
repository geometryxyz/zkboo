#[derive(Debug)]
pub enum Error {
    SerializationError,
    HashLenError(usize, usize),
}

use serde::{Deserialize, Serialize};

use crate::gf2_word::{GF2Word, Value};

/// A party's `View` consists of:
/// - input: the party's initial share of the witness; and
/// - messages: the messages sent to the party.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct View<T: Value> {
    offset: usize,
    pub input: Vec<u8>,
    pub messages: Vec<GF2Word<T>>,
}

impl<T: Value> View<T> {
    pub fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            messages: vec![],
            offset: 0,
        }
    }

    pub fn send_msg(&mut self, msg: GF2Word<T>) {
        self.messages.push(msg);
    }

    /// Read the message at the current `offset`.
    pub fn read_next(&mut self) -> GF2Word<T> {
        let msg_i = self.messages[self.offset];
        self.offset += 1;
        msg_i
    }
}

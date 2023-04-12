
pub struct PartyIndex(pub [u8; 32]);

impl PartyIndex {
    pub fn from_slice(slice: &[u8]) -> anyhow::Result<Self> {
        if slice.len() != 32 {
            bail!("Slice is required to be 32 bytes long");
        }

        Ok({
            let mut result = [0u8; 32];
            result.clone_from_slice(slice);
            PartyIndex(result)
        })
    }

    fn write_as_hex_str(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        self.0.iter().rev().try_for_each(|x| write!(f, "{:02X}", x))
    }
}

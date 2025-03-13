pub fn randombytes(x: &mut [u8], len: usize)
{
  getrandom::fill(&mut x[..len]).unwrap();
}

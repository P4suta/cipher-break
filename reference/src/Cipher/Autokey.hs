-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Ciphers whose key is the message itself after a short primer.
--
-- An autokey never repeats, so it has no period for superposition to find and
-- no column for a frequency count to flatten. What it does have is a primer
-- short enough to exhaust: get it right and the whole message unrolls, get it
-- wrong and every letter after the primer is wrong too. That all-or-nothing
-- behaviour is what makes the index of coincidence a sufficient judge here,
-- and the index of coincidence needs no language.
module Cipher.Autokey
  ( Priming (..)
  , primings
  , encipherAuto
  , decipherAuto
  ) where

import Cipher.Alphabet (Letter)
import Cipher.Periodic (Family, decipherLetter, encipherLetter)

-- | What the key stream continues with once the primer runs out.
data Priming
  = -- | The plaintext, as Vigenere originally proposed.
    PlaintextAuto
  | -- | The ciphertext, which needs no lookahead to decipher.
    CiphertextAuto
  deriving (Eq, Ord, Show, Enum, Bounded)

primings :: [Priming]
primings = [minBound .. maxBound]

encipherAuto :: Priming -> Family -> [Letter] -> [Letter] -> [Letter]
encipherAuto priming fam primer pt
  | null primer = pt
  | otherwise = ct
  where
    ct = zipWith (encipherLetter fam) stream pt
    stream = primer ++ case priming of
      PlaintextAuto -> pt
      CiphertextAuto -> ct

-- | The inverse of 'encipherAuto'.
--
-- The key stream is defined in terms of the plaintext it is being used to
-- produce. That is not circular: position @i@ only ever consults position
-- @i - length primer@, so the recursion is well founded and laziness unrolls
-- it in one pass.
decipherAuto :: Priming -> Family -> [Letter] -> [Letter] -> [Letter]
decipherAuto priming fam primer ct
  | null primer = ct
  | otherwise = pt
  where
    pt = zipWith (decipherLetter fam) stream ct
    stream = primer ++ case priming of
      PlaintextAuto -> pt
      CiphertextAuto -> ct

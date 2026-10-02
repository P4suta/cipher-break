-- SPDX-License-Identifier: MIT OR Apache-2.0

module Cipher.Autokey
  ( Priming (..)
  , primings
  , encipherAuto
  , decipherAuto
  ) where

import Cipher.Alphabet (Letter)
import Cipher.Periodic (Family, decipherLetter, encipherLetter)

data Priming
  =
    PlaintextAuto
  |
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

decipherAuto :: Priming -> Family -> [Letter] -> [Letter] -> [Letter]
decipherAuto priming fam primer ct
  | null primer = ct
  | otherwise = pt
  where
    pt = zipWith (decipherLetter fam) stream ct
    stream = primer ++ case priming of
      PlaintextAuto -> pt
      CiphertextAuto -> ct

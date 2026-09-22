-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | A small deterministic generator for restarting a search.
--
-- A hill climb needs somewhere to start, and starting somewhere arbitrary is
-- the point. It is carried here rather than taken from the system so that a
-- run that breaks a cipher can be replayed exactly.
module Cipher.Random
  ( Seed
  , seed
  , nextWord
  , randomKey
  , randomKeys
  , shuffle
  , shuffles
  ) where

import Cipher.Alphabet (Letter, alphabetSize)
import Data.Bits (shiftL, shiftR, xor)
import Data.Word (Word64)

newtype Seed = Seed Word64
  deriving (Eq, Show)

-- | A generator from any number; zero would be a fixed point of the shift, so
-- it is replaced.
seed :: Word64 -> Seed
seed n = Seed (if n == 0 then 0x2545F4914F6CDD1D else n)

-- | One xorshift64 step.
nextWord :: Seed -> (Word64, Seed)
nextWord (Seed s0) = (s3, Seed s3)
  where
    s1 = s0 `xor` (s0 `shiftL` 13)
    s2 = s1 `xor` (s1 `shiftR` 7)
    s3 = s2 `xor` (s2 `shiftL` 17)

randomKey :: Int -> Seed -> ([Letter], Seed)
randomKey n s0
  | n <= 0 = ([], s0)
  | otherwise =
      let (w, s1) = nextWord s0
          (rest, s2) = randomKey (n - 1) s1
       in (fromIntegral (w `mod` fromIntegral alphabetSize) : rest, s2)

-- | An endless supply of keys of the given length.
randomKeys :: Int -> Seed -> [[Letter]]
randomKeys n s0 = key : randomKeys n s1
  where
    (key, s1) = randomKey n s0

-- | A uniform shuffle, by Fisher and Yates.
--
-- The list is short enough that removing the drawn element by splitting costs
-- nothing worth avoiding, and the quadratic version needs no mutable array.
shuffle :: [a] -> Seed -> ([a], Seed)
shuffle xs s0 = go xs (length xs) s0
  where
    go [] _ s = ([], s)
    go ys n s =
      let (w, s1) = nextWord s
          i = fromIntegral (w `mod` fromIntegral (max 1 n))
       in case splitAt i ys of
            (before, y : after) ->
              let (rest, s2) = go (before ++ after) (n - 1) s1
               in (y : rest, s2)
            (before, []) -> go before (n - 1) s1

-- | An endless supply of shuffles of the same list.
shuffles :: [a] -> Seed -> [[a]]
shuffles xs s0 = ys : shuffles xs s1
  where
    (ys, s1) = shuffle xs s0

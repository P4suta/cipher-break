-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Delastelle's bifid cipher, which takes letters apart before it moves them.
--
-- Each letter becomes a pair of coordinates in a five-by-five square, the
-- coordinates are read off in a different order, and only then are they put
-- back together into letters. A ciphertext letter therefore carries half of
-- one plaintext letter and half of another, which is why every single-letter
-- statistic goes flat and why none of the attacks elsewhere in this package
-- reaches it.
--
-- The square omits one letter of the alphabet, and which one it omits is worth
-- noticing: this ciphertext contains no @I@ but three @J@s, exactly the shape a
-- square that dropped @I@ would leave.
module Cipher.Bifid
  ( standardSquares
  , encipherBifid
  , decipherBifid
  ) where

import Cipher.Alphabet (Letter, alphabetSize)
import Cipher.Square (Square, squareOmitting)
import Data.List (elemIndex)
import Data.Maybe (fromMaybe)

-- | Unkeyed squares, one for each letter that might have been dropped.
standardSquares :: [(Letter, Square)]
standardSquares = [(missing, squareOmitting missing) | missing <- [0 .. alphabetSize - 1]]

-- | Where a letter sits, as a row and a column.
locate :: Square -> Letter -> (Int, Int)
locate sq l = (i `div` 5, i `mod` 5)
  where
    i = fromMaybe 0 (elemIndex l sq)

at :: Square -> (Int, Int) -> Letter
at sq (r, c) = sq !! ((r * 5 + c) `mod` 25)

-- | Split into blocks, dropping nothing: a short final block is enciphered on
-- its own, as the cipher requires.
blocks :: Int -> [a] -> [[a]]
blocks n xs
  | n <= 0 = [xs]
  | null xs = []
  | otherwise = let (b, rest) = splitAt n xs in b : blocks n rest

encipherBifid :: Int -> Square -> [Letter] -> [Letter]
encipherBifid period sq = concatMap step . blocks period
  where
    step block =
      let coords = map (locate sq) block
          row = map fst coords ++ map snd coords
       in pairUp row
    pairUp (r : c : rest) = at sq (r, c) : pairUp rest
    pairUp _ = []

decipherBifid :: Int -> Square -> [Letter] -> [Letter]
decipherBifid period sq = concatMap step . blocks period
  where
    step block =
      let flat = concatMap (\l -> let (r, c) = locate sq l in [r, c]) block
          (rows, cols) = splitAt (length flat `div` 2) flat
       in zipWith (curry (at sq)) rows cols

-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Playfair and its two-square and four-square relatives.
--
-- All three encipher two letters at a time from squares of 25, which flattens
-- single-letter statistics and puts them out of reach of everything that
-- counts letters. Playfair leaves one tell, and it is decisive: its rules can
-- never send a pair of distinct letters to a pair of equal ones, so a
-- ciphertext holding a doubled letter on an even boundary did not come from
-- it, whatever else it came from.
module Cipher.Playfair
  ( decipherPlayfair
  , encipherPlayfair
  , playfairPossible
  , decipherFourSquare
  , encipherFourSquare
  ) where

import Cipher.Alphabet (Letter)
import Cipher.Square (Square, squareSize)
import Data.List (elemIndex)
import Data.Maybe (fromMaybe)

locate :: Square -> Letter -> (Int, Int)
locate sq l = (i `div` squareSize, i `mod` squareSize)
  where
    i = fromMaybe 0 (elemIndex l sq)

at :: Square -> (Int, Int) -> Letter
at sq (r, c) = sq !! ((r `mod` squareSize) * squareSize + (c `mod` squareSize))

pairs :: [a] -> [(a, a)]
pairs (a : b : rest) = (a, b) : pairs rest
pairs _ = []

unpair :: [(Letter, Letter)] -> [Letter]
unpair = concatMap (\(a, b) -> [a, b])

step :: Int -> Square -> (Letter, Letter) -> (Letter, Letter)
step direction sq (a, b)
  | r1 == r2 = (at sq (r1, c1 + direction), at sq (r2, c2 + direction))
  | c1 == c2 = (at sq (r1 + direction, c1), at sq (r2 + direction, c2))
  | otherwise = (at sq (r1, c2), at sq (r2, c1))
  where
    (r1, c1) = locate sq a
    (r2, c2) = locate sq b

encipherPlayfair :: Square -> [Letter] -> [Letter]
encipherPlayfair sq = unpair . map (step 1 sq) . pairs

decipherPlayfair :: Square -> [Letter] -> [Letter]
decipherPlayfair sq = unpair . map (step (-1) sq) . pairs

-- | Whether a ciphertext could have come from Playfair at all.
--
-- One check, no key, no search: a repeated letter inside a digraph is
-- impossible under every one of the three rules.
playfairPossible :: [Letter] -> Bool
playfairPossible = all (uncurry (/=)) . pairs

-- | Four-square, given the two keyed squares; the plain square is the third
-- argument, and is usually the alphabet in order.
encipherFourSquare :: Square -> Square -> Square -> [Letter] -> [Letter]
encipherFourSquare topRight bottomLeft plain = unpair . map mix . pairs
  where
    mix (a, b) =
      let (r1, c1) = locate plain a
          (r2, c2) = locate plain b
       in (at topRight (r1, c2), at bottomLeft (r2, c1))

decipherFourSquare :: Square -> Square -> Square -> [Letter] -> [Letter]
decipherFourSquare topRight bottomLeft plain = unpair . map unmix . pairs
  where
    unmix (a, b) =
      let (r1, c2) = locate topRight a
          (r2, c1) = locate bottomLeft b
       in (at plain (r1, c1), at plain (r2, c2))

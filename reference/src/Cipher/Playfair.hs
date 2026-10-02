-- SPDX-License-Identifier: MIT OR Apache-2.0

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

playfairPossible :: [Letter] -> Bool
playfairPossible = all (uncurry (/=)) . pairs

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

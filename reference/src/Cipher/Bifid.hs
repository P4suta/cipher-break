-- SPDX-License-Identifier: MIT OR Apache-2.0

module Cipher.Bifid
  ( standardSquares
  , encipherBifid
  , decipherBifid
  ) where

import Cipher.Alphabet (Letter, alphabetSize)
import Cipher.Square (Square, squareOmitting)
import Data.List (elemIndex)
import Data.Maybe (fromMaybe)

standardSquares :: [(Letter, Square)]
standardSquares = [(missing, squareOmitting missing) | missing <- [0 .. alphabetSize - 1]]

locate :: Square -> Letter -> (Int, Int)
locate sq l = (i `div` 5, i `mod` 5)
  where
    i = fromMaybe 0 (elemIndex l sq)

at :: Square -> (Int, Int) -> Letter
at sq (r, c) = sq !! ((r * 5 + c) `mod` 25)

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

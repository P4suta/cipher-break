-- SPDX-License-Identifier: MIT OR Apache-2.0

module Cipher.Ngram
  ( Model (..)
  , mkModel
  , train
  , score
  , grams
  , render
  , parseModel
  , loadModel
  ) where

import Cipher.Alphabet (Letter, alphabetSize, fromLetters, toLetters)
import Data.Array.Unboxed (UArray, accumArray, elems, listArray, (!))
import Data.Maybe (mapMaybe)

data Model = Model
  { modelOrder :: !Int
  , modelTotal :: !Double
  , modelCounts :: !(UArray Int Int)
  , modelLogProb :: UArray Int Double
  }

slots :: Int -> Int
slots n = alphabetSize ^ n

mkModel :: Int -> UArray Int Int -> Model
mkModel order cs = Model order total cs table
  where
    total = max 1 (fromIntegral (sum (elems cs)))
    unseen = log (0.01 / total)
    table =
      listArray (0, slots order - 1) [if c == 0 then unseen else log (fromIntegral c / total) | c <- elems cs]

grams :: Int -> [Letter] -> [Int]
grams order ls
  | order < 1 = []
  | otherwise = go (0 :: Int) 0 ls
  where
    m = slots order
    go seen acc (x : xs) =
      let acc' = (acc * alphabetSize + x) `mod` m
          seen' = seen + 1
       in if seen' >= order then acc' : go seen' acc' xs else go seen' acc' xs
    go _ _ [] = []

train :: Int -> [Letter] -> Model
train order ls = mkModel order cs
  where
    cs :: UArray Int Int
    cs = accumArray (+) 0 (0, slots order - 1) [(g, 1) | g <- grams order ls]

score :: Model -> [Letter] -> Double
score m ls
  | null gs = 0
  | otherwise = sum [table ! g | g <- gs] / fromIntegral (length gs)
  where
    gs = grams (modelOrder m) ls
    table = modelLogProb m

render :: Int -> Model -> String
render cutoff m =
  unlines $
    ("order " ++ show (modelOrder m))
      : [ fromLetters (spell (modelOrder m) i) ++ " " ++ show c
        | (i, c) <- zip [0 ..] (elems (modelCounts m))
        , c >= cutoff
        ]

spell :: Int -> Int -> [Letter]
spell order i = reverse (take order (go i))
  where
    go n = (n `mod` alphabetSize) : go (n `div` alphabetSize)

parseModel :: String -> Maybe Model
parseModel txt = case lines txt of
  (header : rest)
    | ["order", o] <- words header
    , [(order, "")] <- reads o ->
        Just (mkModel order (accumArray (+) 0 (0, slots order - 1) (mapMaybe (entry order) rest)))
  _ -> Nothing
  where
    entry order line = case words line of
      [g, c]
        | length g == order
        , [(n, "")] <- reads c ->
            Just (gramIndex (toLetters g), n :: Int)
      _ -> Nothing
    gramIndex = foldl (\acc l -> acc * alphabetSize + l) 0

loadModel :: FilePath -> IO (Maybe Model)
loadModel path = parseModel <$> readFile path

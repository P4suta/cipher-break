-- SPDX-License-Identifier: MIT OR Apache-2.0

module Cipher.Sweep
  ( Trial (..)
  , Search (..)
  , best
  , topScore
  , sweep
  , sweepTwoStage
  , Outcome (..)
  ) where

import Cipher.Alphabet (Letter)
import Cipher.Random (Seed, shuffles)
import qualified Data.Set as S

data Trial = Trial
  { trialScore :: Double
  , trialLabel :: String
  , trialPlain :: [Letter]
  }
  deriving (Eq, Ord, Show)

data Search = Search
  { searchName :: String
  , searchRun :: [Letter] -> [(String, [Letter])]
  }

best :: Int -> ([Letter] -> Double) -> [(String, [Letter])] -> [Trial]
best k score = S.toDescList . foldl step S.empty
  where
    step acc (label, plain) =
      let acc' = S.insert (Trial (score plain) label plain) acc
       in if S.size acc' > k then S.deleteMin acc' else acc'

topScore :: ([Letter] -> Double) -> [(String, [Letter])] -> Double
topScore score = foldl (\acc (_, plain) -> max acc (score plain)) (-1 / 0)

data Outcome = Outcome
  { outcomeName :: String
  , outcomeBest :: [Trial]
  , outcomeNull :: [Double]
  }

sweep :: Int -> Int -> ([Letter] -> Double) -> Search -> [Letter] -> Seed -> Outcome
sweep keep trials score search ct s0 =
  Outcome
    (searchName search)
    (best keep score (searchRun search ct))
    [topScore score (searchRun search shuffled) | shuffled <- take trials (shuffles ct s0)]

sweepTwoStage ::
  Int ->
  Int ->
  Int ->
  ([Letter] -> Double) ->
  ([Letter] -> Double) ->
  Search ->
  [Letter] ->
  Seed ->
  Outcome
sweepTwoStage keep shortlist trials filterBy judge search ct s0 =
  Outcome
    (searchName search)
    (stage (searchRun search ct))
    [leader (stage (searchRun search shuffled)) | shuffled <- take trials (shuffles ct s0)]
  where
    stage proposals =
      best keep judge [(trialLabel t, trialPlain t) | t <- best shortlist filterBy proposals]
    leader trials' = case trials' of
      (t : _) -> trialScore t
      [] -> -1 / 0

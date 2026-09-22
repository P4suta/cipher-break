-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Running a whole key space, and knowing what its best result is worth.
--
-- Trying 157,248 keys and keeping the one that scores highest is not evidence
-- of anything on its own: the largest of 157,248 draws from a harmless
-- distribution is large too. Every sweep here therefore reports the best it
-- found beside the best the identical sweep finds in shuffled text, which is
-- the only number that makes the first one mean something.
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

-- | One key tried, with what it produced and what that scored.
data Trial = Trial
  { trialScore :: Double
  , trialLabel :: String
  , trialPlain :: [Letter]
  }
  deriving (Eq, Ord, Show)

-- | A named key space, as the decipherments it proposes for a ciphertext.
data Search = Search
  { searchName :: String
  , searchRun :: [Letter] -> [(String, [Letter])]
  }

-- | The best @k@ candidates, highest first, holding no more than @k@ at a time.
best :: Int -> ([Letter] -> Double) -> [(String, [Letter])] -> [Trial]
best k score = S.toDescList . foldl step S.empty
  where
    step acc (label, plain) =
      let acc' = S.insert (Trial (score plain) label plain) acc
       in if S.size acc' > k then S.deleteMin acc' else acc'

-- | The single best score, without keeping anything else.
topScore :: ([Letter] -> Double) -> [(String, [Letter])] -> Double
topScore score = foldl (\acc (_, plain) -> max acc (score plain)) (-1 / 0)

-- | What a sweep found, and what the same sweep finds in noise.
data Outcome = Outcome
  { outcomeName :: String
  , outcomeBest :: [Trial]
  , outcomeNull :: [Double]
  }

-- | Run a search on the text, then on shuffles of it.
sweep :: Int -> Int -> ([Letter] -> Double) -> Search -> [Letter] -> Seed -> Outcome
sweep keep trials score search ct s0 =
  Outcome
    (searchName search)
    (best keep score (searchRun search ct))
    [topScore score (searchRun search shuffled) | shuffled <- take trials (shuffles ct s0)]

-- | A cheap filter, then a costly judge, with the whole pair calibrated.
--
-- Scoring a hundred thousand candidates under a bank of n-gram models is too
-- slow to contemplate, and scoring them under the index of coincidence alone
-- is too blunt to trust. Running the blunt measure first and the sharp one
-- over what survives costs almost nothing extra, and the null has to run both
-- stages too: a shortlist is itself a choice, and choices inflate maxima.
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

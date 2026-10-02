-- SPDX-License-Identifier: MIT OR Apache-2.0

module Cipher.Anneal
  ( anneal
  ) where

import Cipher.Random (Seed, nextWord)

unit :: Seed -> (Double, Seed)
unit s0 = (fromIntegral w / 18446744073709551616.0, s1)
  where
    (w, s1) = nextWord s0

anneal ::
  (state -> Double) ->
  (Seed -> state -> (state, Seed)) ->
  Int ->
  (Double, Double) ->
  state ->
  Seed ->
  (state, Double)
anneal score move steps (hot, cold) start s0 = go 0 start (score start) start (score start) s0
  where
    ratio
      | steps <= 1 || hot <= 0 = 1
      | otherwise = (cold / hot) ** (1 / fromIntegral (steps - 1))
    go step current currentScore bestState bestScore s
      | step >= steps = (bestState, bestScore)
      | otherwise =
          let (candidate, s1) = move s current
              candidateScore = score candidate
              temperature = hot * ratio ^ step
              (roll, s2) = unit s1
              accepted =
                candidateScore >= currentScore
                  || (temperature > 0 && roll < exp ((candidateScore - currentScore) / temperature))
              (nextState, nextScore)
                | accepted = (candidate, candidateScore)
                | otherwise = (current, currentScore)
              (keptState, keptScore)
                | candidateScore > bestScore = (candidate, candidateScore)
                | otherwise = (bestState, bestScore)
           in go (step + 1) nextState nextScore keptState keptScore s2

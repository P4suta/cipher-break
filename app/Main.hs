-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | The command line: @train@ learns a language, @analyze@ describes a
-- ciphertext and @solve@ reads it.
module Main (main) where

import Cipher.Alphabet (Letter, alphabetSize, fromLetters, letterChar, toLetters)
import Cipher.Attack
  ( Candidate (..)
  , chiKey
  , climbAttack
  , icByPeriod
  , periodAttack
  , rank
  , rescore
  , searchKeys
  )
import Cipher.Fitness (Lexicon (..), loadLexicon, segment, wordCover)
import Cipher.Kasiski (Repeat (..), factorTally, repeats)
import Cipher.Ngram (Model (..), loadModel, render, score, train)
import Cipher.Periodic (Family (..), decipher, families)
import Cipher.Stats (chiSquared, counts, indexOfCoincidence)
import Cipher.Random (seed)
import Cipher.Superpose (Significance (..), alignment, significance)
import Cipher.Triage (Verdict (..), triage)
import Data.List (sortOn)
import qualified Data.Set as S
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)
import Text.Printf (printf)

defaultDict :: FilePath
defaultDict = "/usr/share/dict/words"

defaultModel :: FilePath
defaultModel = "data/english-quadgrams.txt"

-- | Periods worth trying: past a quarter of the text a column holds too few
-- letters for any statistic to mean anything.
maxPeriod :: Int
maxPeriod = 16

-- | How many random starting keys each hill climb gets on top of the two fixed
-- ones.
restarts :: Int
restarts = 12

usage :: String
usage =
  unlines
    [ "usage: cipher-break analyze FILE [--null N]"
    , "       cipher-break solve FILE [--dict PATH] [--model PATH] [--top N]"
    , "       cipher-break triage FILE [--trials N]"
    , "       cipher-break reduce FILE --period N"
    , "       cipher-break train [--order N] [--cutoff N]   (corpus on stdin)"
    ]

main :: IO ()
main = do
  args <- getArgs
  case args of
    ("analyze" : path : opts) -> do
      ct <- readLetters path
      analyze (readOption "--null" 200 opts) ct
    ("solve" : path : opts) -> do
      ct <- readLetters path
      solve opts ct
    ("triage" : path : opts) -> do
      ct <- readLetters path
      report' (triage (readOption "--trials" 20000 opts) ct (seed 0xC0FFEE))
    ("reduce" : path : opts) -> do
      ct <- readLetters path
      reduce (readOption "--period" 4 opts) ct
    ("train" : opts) -> do
      corpus <- toLetters <$> getContents
      putStr (render (readOption "--cutoff" 3 opts) (train (readOption "--order" 4 opts) corpus))
    _ -> hPutStrLn stderr usage >> exitFailure

readLetters :: FilePath -> IO [Letter]
readLetters path = toLetters <$> readFile path

option :: String -> String -> [String] -> String
option name fallback (k : v : rest)
  | k == name = v
  | otherwise = option name fallback (v : rest)
option _ fallback _ = fallback

readOption :: (Read a) => String -> a -> [String] -> a
readOption name fallback opts = case reads (option name "" opts) of
  [(v, "")] -> v
  _ -> fallback

-- | Everything that can be said about the ciphertext before guessing a key.
analyze :: Int -> [Letter] -> IO ()
analyze trials ct = do
  printf "ciphertext   %s\n" (fromLetters ct)
  printf "letters      %d\n" (length ct)
  printf "IC           %.4f   (random 0.0385, English 0.0667)\n" (indexOfCoincidence ct)
  printf "chi-squared  %.1f    (against English letter frequencies)\n" (chiSquared ct)

  putStrLn "\nletter counts"
  putStrLn (unwords [[letterChar i] | i <- [0 .. 25]])
  putStrLn (unwords [printf "%d" c | c <- counts ct])

  putStrLn "\nindex of coincidence by period"
  mapM_ reportPeriod [1 .. maxPeriod]

  printf "\nsuperposition: IC once the columns are aligned, against %d shuffles\n" trials
  putStrLn "  p      IC   null mean    sd       z  relative key"
  mapM_ reportMerged [1 .. maxPeriod]

  putStrLn "\nrepeated substrings"
  let found = concatMap (`repeats` ct) [4, 3, 2]
  if null found
    then putStrLn "  (none)"
    else mapM_ reportRepeat found

  let distances = concatMap repeatDistances found
  putStrLn "\nperiods dividing those distances"
  mapM_
    (\(p, n) -> printf "  %2d  %d\n" p n)
    (take 6 (sortOn (negate . snd) (factorTally maxPeriod distances)))
  where
    reportPeriod n = do
      let v = icByPeriod ct n
      printf "  %2d  %.4f  %s\n" n v (replicate (round (v * 400)) '#')
    reportMerged n =
      let sig = significance trials n ct (seed (0x9E3779B97F4A7C15 + fromIntegral n))
       in printf
            "  %2d  %.4f     %.4f  %.4f  %+6.2f  %s\n"
            n
            (sigObserved sig)
            (sigNullMean sig)
            (sigNullSd sig)
            (sigZ sig)
            (fromLetters (alignment n ct))
    reportRepeat r =
      printf
        "  %-4s at %s  distances %s\n"
        (repeatText r)
        (show (repeatPositions r))
        (show (repeatDistances r))

-- | Run every attack and print the best readings.
solve :: [String] -> [Letter] -> IO ()
solve opts ct = do
  let dictPath = option "--dict" defaultDict opts
      modelPath = option "--model" defaultModel opts
      top = readOption "--top" (8 :: Int) opts
  lexicon <- loadLexicon dictPath
  loaded <- loadModel modelPath
  model <- case loaded of
    Just m -> pure m
    Nothing -> hPutStrLn stderr ("cannot read an n-gram model from " ++ modelPath) >> exitFailure

  printf "lexicon      %d words from %s\n" (S.size (lexWords lexicon)) dictPath
  printf "model        order %d over %.0f grams from %s\n" (modelOrder model) (modelTotal model) modelPath

  let english = wordCover lexicon
      likely = score model
      keys = [toLetters w | w <- S.toList (lexWords lexicon)]
      proposals = [(fam, key) | fam <- families, key <- keys]
      -- The n-gram model is cheap and keeps the field open; the word cover is the costly judge and only ever sees the shortlist.
      byKeyword = rescore english (searchKeys likely 400 ct proposals)
      byPeriod = periodAttack english [1 .. maxPeriod] ct
      byClimb = rescore english (climbAttack likely restarts [1 .. maxPeriod] ct)

  section "dictionary keys" lexicon likely (rank top byKeyword)
  section "chi-squared per period" lexicon likely (rank top byPeriod)
  section "hill climbing per period" lexicon likely (rank top byClimb)
  section "best overall" lexicon likely (rank top (byKeyword ++ byPeriod ++ byClimb))

  putStrLn "\nkeys the chi-squared fit chose, period by period"
  mapM_ reportKey [(fam, n) | fam <- families, n <- [1 .. 8]]
  where
    reportKey (fam, n) = printf "  %-16s %2d  %s\n" (show fam) n (fromLetters (chiKey fam n ct))

section :: String -> Lexicon -> ([Letter] -> Double) -> [Candidate] -> IO ()
section title lexicon likely cands = do
  printf "\n=== %s ===\n" title
  mapM_ (uncurry (report lexicon likely)) (zip [1 :: Int ..] cands)

report :: Lexicon -> ([Letter] -> Double) -> Int -> Candidate -> IO ()
report lexicon likely i c = do
  printf
    "#%d  cover %+6.2f  ngram %+6.3f  %-16s key %s\n"
    i
    (candScore c)
    (likely (candPlain c))
    (show (candFamily c))
    (fromLetters (candKey c))
  printf "      %s\n" (fromLetters (candPlain c))
  printf "      %s\n" (unwords (segment lexicon (candPlain c)))

-- | Undo the period, then show every reading the remaining unknown allows.
--
-- Superposition recovers the key only up to its first letter, so what it hands
-- back is the plaintext under one shift that no amount of further statistics
-- can pin down. There are 26 of those, and 26 more if the family reverses the
-- alphabet on the way, as Beaufort does. Fifty-two lines is a small enough
-- haystack to read, and reading them needs no guess about the language.
reduce :: Int -> [Letter] -> IO ()
reduce period ct = do
  let shifts = alignment period ct
      aligned = decipher Vigenere shifts ct
  printf "period %d, relative key %s\n" period (fromLetters shifts)
  printf "IC of the reduced text  %.4f\n\n" (indexOfCoincidence aligned)
  putStrLn "the alphabet as it stands"
  mapM_ (line aligned) [0 .. alphabetSize - 1]
  putStrLn "\nthe alphabet reversed, as a Beaufort key would leave it"
  mapM_ (line (map negate aligned)) [0 .. alphabetSize - 1]
  where
    line txt k =
      printf "  %s  %s\n" [letterChar k] (fromLetters (map (subtract k) txt))

-- | Print the triage table.
report' :: [Verdict] -> IO ()
report' vs = do
  printf "%-22s %10s %10s %8s %8s\n" "statistic" "observed" "null mean" "z" "P"
  mapM_ row vs
  where
    row v =
      printf
        "%-22s %10.4f %10.4f %+8.2f %8.4f\n"
        (verdictName v)
        (verdictObserved v)
        (verdictMean v)
        (verdictZ v)
        (verdictP v)

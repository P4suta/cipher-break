<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# cipher-break

A cryptanalysis workbench for classical polyalphabetic ciphers, built around one 72-letter ciphertext of unknown origin.

The ciphertext is in `data/ciphertext.txt`:

```
JCRSAJTGSJEYEXYKKZZSHVUOCTRFRCRPFVYPLKPPLGRHVVBBTBRSXSWXGGTYTVKQNGSCHVGF
```

Nothing is known about it beyond that.
Not the cipher, not the key, not the language of the plaintext.
That last gap drives the design: an attack that needs a table of English letter frequencies is worth little here, so the tools that need no language at all come first.

## Commands

```
cipher-break triage  FILE [--trials N]                     is this even structured?
cipher-break analyze FILE [--null N]                       periods, repeats, superposition
cipher-break reduce  FILE --period N                       undo a period, show every reading
cipher-break solve   FILE [--dict PATH] [--model PATH]     attacks that assume English
cipher-break train   [--order N] [--cutoff N]              learn an n-gram model from stdin
```

`mise run check` builds with warnings denied and runs the suite.

## What each command is for

`triage` compares the text against a large sample of uniform random letters, one statistic at a time, and reports the share of the sample that matched or beat it.
It assumes nothing whatever, which is why it runs first.

`analyze` looks for a period.
The index of coincidence per period is the familiar measure and is reported, but it rises with the period whether or not a period is there, so the number that decides anything is the one beside it: the same statistic recomputed after Kerckhoffs' superposition, and compared against the same procedure run on shuffles of the same letters.
Aligning columns means choosing shifts that maximise a statistic, and a shuffled text offers that choice just as readily; only the margin between them is evidence.

`reduce` applies the alignment and prints all 52 readings the remaining unknown allows — 26 shifts, and 26 more for the families that reverse the alphabet.
Superposition recovers a key only up to its first letter, and no further statistic can close that gap, but 52 lines can simply be read, in any language.

`solve` is the part that does assume English: a dictionary attack over every key in the system word list, a chi-squared fit per column, and hill climbing against a quadgram model, all ranked by the best split of the plaintext into dictionary words.

`train` builds the quadgram model.
The committed `data/english-quadgrams.txt` was trained on 7.9 million letters of English prose; its counts agree exactly with an independent count made in Python.

## What the tools say about this ciphertext

The suite is known to work: its tests plant a period-4 and a period-5 key in English text and require every attack to recover it.
On this ciphertext all of them come back empty.

| statistic | observed | random mean | P |
| --- | --- | --- | --- |
| index of coincidence | 0.0438 | 0.0384 | 0.09 |
| adjacent doubles | 6 | 2.73 | 0.06 |
| repeated bigrams | 6 | 3.54 | 0.14 |
| repeated trigrams | 0 | 0.13 | 1.00 |
| digraph IC | 0.0032 | 0.0015 | 0.23 |
| distinct letters | 23 | 24.5 | 0.18 |

Against 50,000 random texts of the same length, nothing separates this one from them.

Superposition is the one place a signal appears.
Periods 4, 8, 12 and 16 all sit about 2.5 standard deviations above their null while every other period sits at zero, and a period-4 key is also a period-8, -12 and -16 key, so those four are one observation rather than four.
One observation at z = 2.5, chosen as the largest of sixteen, is roughly a one-in-twenty coincidence.
It is worth recording and it is not worth believing.
The relative key it proposes is `ACYZ`, and none of the 52 readings that follow from it resembles a language.

The English-assuming attacks add nothing: 221,705 dictionary keys across three families, a chi-squared fit at every period up to 16, and hill climbing with fourteen restarts per family and period all return text that scores far below English on the quadgram model.

The honest reading is that 72 letters is short.
A Vigenere key of eight letters leaves nine letters per column, which no statistic can work with; a running key, an autokey, a one-time pad or any modern cipher leaves nothing at all.
"Indistinguishable from random" is a statement about the reach of these methods at this length, not about the text.

## Licence

MIT or Apache-2.0, at your option.

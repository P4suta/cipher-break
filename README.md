<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# cipher-break

Break a classical cipher, or find out honestly that you cannot.

```console
$ cb WKHTXLFNEURZQIRAMXPSVRYHUWKHODCBGRJDQGWKHQUXQVDZDBLQWRWKHIRUHVW

VERDICT ──────────────────────────────────────────────────────────────
  READ  affine and caesar
  key       a=1 b=23
  language  en  (fit +33.1s, text of this length reaches +30.2s)

  THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDTHENRUNSAWAYINTOTHEFOREST
```

Hand it a ciphertext — as a file, as a literal run of letters, or on standard input — and it runs its whole catalogue, calibrates itself against the machine it is on, and tells you either what the message is or exactly what it ruled out on the way to not knowing.

No corpus to point it at, no language to declare, no key length to guess.
The language models are built into the binary.

## Install

```console
$ cargo install --path .              # cb
$ cargo install --path . --features gpu   # cb, with the GPU backend
```

## Use

```
cb <ciphertext|file|->                run the whole catalogue and report
cb solve   <input> [options]          the same, spelled out
cb report  <input>                    diagnostics only: what the text is
cb try     <attack> <input>           run one attack by name
cb list                               every attack in the catalogue
cb devices                            what this machine can compute with
cb train   [--order N] [--cutoff N]   learn a model from a corpus on stdin
```

| option | |
| --- | --- |
| `--effort quick\|normal\|deep\|max` | how hard to search |
| `--depth N` | exhaust keys up to N letters long |
| `--nulls N` | shuffles each attack is calibrated against |
| `--gpu` | run the big exhaustive sweeps on the GPU |
| `--models DIR` | language models instead of the built-in bank |
| `--seed N` | make a run reproducible |
| `--top N`, `--plain` | how much to show, and without colour |

## What it knows

| family | attacks | coverage |
| --- | --- | --- |
| monoalphabetic | Caesar, Atbash, affine, simple substitution | every affine key; substitution by annealing |
| periodic | Vigenere, Beaufort, variant Beaufort, Porta | every key to the depth you ask for, then hill climbing to period 16 |
| autokey | plaintext- and ciphertext-primed, all three families | every primer to the depth you ask for |
| polygraphic | Hill 2×2, Playfair, four-square | all 157,248 Hill keys; squares by annealing |
| fractionating | bifid, keyed and unkeyed | every unkeyed square and period; keyed by annealing |
| transposition | columnar to width 8, rail fence | every column order and every height |
| concealment | null ciphers: every nth letter, forwards and back | every stride and offset to 12 |

Adding one means writing an `Attack`: a name, a key space, and a way of searching it.
Everything else — the calibration, the nulls, the ranking, the report — works on it the day it arrives.

## The two ideas it is built on

**Nothing is evidence until its null is known.** Keeping the best of 157,248 keys is not a finding: the largest of 157,248 draws from a harmless distribution is large too.
Every attack therefore runs twice, once on the ciphertext and once on shuffles of it, and the margin between them is what decides.
This is not decoration.
On a 72-letter message, annealing a bifid square reaches a score that would pass for a language — and reaches the same score on noise.
The null is the only thing that catches it.

**The judge must not assume a language.** Eighteen n-gram models ship inside the binary, from Czech to Japanese romaji, and every candidate is scored under all of them.
Scores are reported in deviations above what random letters *of the same length* achieve, so a twelve-letter fragment and a seventy-letter message can be compared without the short one winning for being short.

Both ideas were earned rather than designed.
The bifid attack silently did not work until a planted key was demanded of it; the tool read a plain Caesar cipher as a sixteen-letter Vigenere key until selection was changed from the raw score to the margin over the null; and it missed a message hidden as every third letter until scores were made length-aware.
Each of those is now a test.

## Two implementations

`reference/` is Haskell: the same algorithms, written to be read.
The root is Rust: the same algorithms, written to be fast.
They share `data/`, so a model trained by either is read by both, and `mise run agree` checks that they still answer alike.

## Speed

Apple M5 Pro, 18 cores, on a 72-letter message:

| sweep | keys | CPU | GPU |
| --- | --- | --- | --- |
| Vigenere period 4 | 1,370,928 | 0.04 s | — |
| Vigenere period 5 | 35,644,128 | 0.80 s | 0.42 s |
| Vigenere period 6 | 926,747,328 | 20.8 s | **2.8 s** |
| Vigenere period 7 | 24,095,430,528 | ~9 min | **72 s** |

That is 337 million keys a second on the device, and the two backends agree key for key.

The GPU kernel never materialises a plaintext: a trigram index can be carried forward one letter at a time, so a thread holds five `vec4` accumulators and the running index and nothing else.
Its first version kept the key and the accumulators in function-scope arrays — 192 bytes a thread, which spills out of registers — and beat eighteen CPU cores by only a little.
The rewrite is seven times faster than the CPU rather than two.

On the CPU side the win was the same kind of thing: the eighteen models are interleaved so every language's value for a gram sits together, which turns eighteen scattered cache lines per gram into two adjacent ones.

## Licence

MIT or Apache-2.0, at your option.

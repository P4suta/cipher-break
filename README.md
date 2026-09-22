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
cipher-break triage    FILE [--trials N]                    is this even structured?
cipher-break calibrate FILE [--samples N]                   how does real language look, cut to this length?
cipher-break analyze   FILE [--null N]                      periods, repeats, superposition, all against their nulls
cipher-break sweep     FILE [--which NAME] [--nulls N]      exhaust a key space, and calibrate the exhausting
cipher-break reduce    FILE --period N                      undo a period, show every reading
cipher-break solve     FILE [--dict PATH] [--model PATH]    the attacks that assume English
cipher-break train     [--order N] [--cutoff N]             learn an n-gram model from stdin
```

`mise run check` builds with warnings denied and runs the suite.

## The two ideas the tool is built on

**Nothing is evidence until its null is known.** Aligning columns, choosing the best of sixteen periods, keeping the best of 157,248 keys — each of those maximises a statistic, and maximising raises a statistic on any text whatever.
So every number here is reported beside the same procedure run on text that is known to hide nothing: shuffles of the same letters, or uniform random letters.
The margin between them is the finding; the number on its own is not.

**The judge must not assume a language.** The index of coincidence is the one measure that says "this is a language" without saying which, and it is weak: it counts letters and ignores their order, so it cannot tell a plaintext from an anagram of one.
Swapping the rows of a Hill deciphering matrix swaps the letters within every digraph and leaves it untouched, which is exactly how a true key can fail to come first in a sweep that trusts it.
`Cipher.Polyglot` is the answer: a bank of n-gram models, one per language, scoring each candidate under all of them and keeping the best fit.
Eighteen are committed in `data/models`, from Czech to Japanese romaji, trained on comparable amounts of text.

That bank is calibrated, and the calibration is what makes every result below readable:

| text | language fit |
| --- | --- |
| real prose, 72 letters, any of the 18 languages | **−6.4 to −7.8** |
| uniform random letters | −14.0 |
| this ciphertext | −14.4 |

Real language and noise are eleven points apart, which on these samples is between 11 and 29 standard deviations.
There is no middle ground to be confused by.

## What the tools say about this ciphertext

The suite is known to work: it plants keys in known plaintext and requires every attack to recover them — a Vigenere period, a Porta key, an autokey primer, a Hill matrix, a bifid square.
On this ciphertext all of them come back empty.

### It is not distinguishable from random letters

Against 20,000 random texts of the same length:

| statistic | observed | random mean | P |
| --- | --- | --- | --- |
| index of coincidence | 0.0438 | 0.0384 | 0.09 |
| adjacent doubles | 6 | 2.73 | 0.06 |
| repeated bigrams | 6 | 3.54 | 0.14 |
| repeated trigrams | 0 | 0.13 | 1.00 |
| digraph IC | 0.0032 | 0.0015 | 0.23 |
| distinct letters | 23 | 24.5 | 0.18 |
| language fit | −14.41 | −14.00 | 0.85 |

### Everything that preserves letter counts is excluded

A simple substitution and a transposition both hand the plaintext's index of coincidence straight through, so whatever produced this text must have a plaintext with an index of coincidence of 0.0438.
Cut 3,000 windows of 72 letters from each of eighteen languages and ask how many are that flat:

| | en | de | fr | es | it | nl | pl | fi | ja |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| mean IC | 0.067 | 0.073 | 0.077 | 0.074 | 0.075 | 0.079 | 0.057 | 0.084 | 0.077 |
| z of 0.0438 | −2.6 | −2.3 | −3.1 | −4.0 | −4.0 | −2.4 | −1.8 | −3.2 | −4.3 |

Essentially none.
That rules out every monoalphabetic substitution — Caesar, affine, keyword, arbitrary — every transposition — columnar, double, rail fence, route — and any stack of the two.
Playfair is excluded separately and structurally: it can never emit a doubled letter within a digraph, and this text has `PP`, `VV` and `BB` on even boundaries.

### Nothing in the searchable key spaces is a language

| search | key space | exhaustive? | best fit | noise reaches |
| --- | --- | --- | --- | --- |
| Vigenere, Beaufort, variant Beaufort, period 1–3 | 54,834 | yes | −12.06 | −11.57 |
| the same, period 1–16 | hill climbing, 14 restarts each | no | −9.03 | −8.83 |
| Porta, period 1–5 | 402,233 | yes | −11.98 | −11.32 |
| autokey, both primings, three families, primer 1–4 | 2,851,524 | yes | −11.83 | −11.71 |
| Hill 2×2 | 157,248 | yes | −11.39 | −11.63 |
| bifid, unkeyed square, every omitted letter | 624 | yes | −12.07 | −12.34 |
| dictionary keys over the system word list | 665,115 | yes | — | — |

Every one of them lands where noise lands, and eleven points short of any language.

The hill-climbing row is the instructive one.
It scores best of all at −9.03, and it is the emptiest result in the table: shuffled text, climbed the same way, reaches −9.02 on average and −8.83 at its best.
Sixteen free key letters over 72 positions can force any text into that shape, and the null is what says so.

### The one signal, and why it is not one

Two statistics that measure it differently — the plain index of coincidence within the columns, and the index of coincidence after the columns are aligned by superposition — both single out periods 4, 8, 12 and 16 at about z = +2.5, with every other period at zero.
A period-4 key is also a period-8, -12 and -16 key, so those four are one observation.

Tested as the one claim it is, with the maximum over sixteen periods calibrated against the maximum over sixteen periods in shuffled text:

| statistic | peak | z | noise peaks at | P |
| --- | --- | --- | --- | --- |
| column IC | period 8 | +2.80 | +1.86 | 0.110 |
| superposition IC | period 8 | +3.08 | +1.93 | 0.097 |

One time in ten, noise does this.
The relative key superposition proposes at period 4 is `ACYZ`, and none of the 52 readings that follow from it resembles a language in any of the eighteen.

## What is left

Not everything can be exhausted, and what remains is what a short message protects best: a Vigenere key of eight letters or more, which leaves nine letters per column and nothing for a statistic to hold; a keyed bifid or four-square square, at 25 factorial; a running key; a one-time pad; anything modern.

The honest reading is that 72 letters is short.
"Indistinguishable from random" is a statement about the reach of these methods at this length, and not about the text.

## Licence

MIT or Apache-2.0, at your option.

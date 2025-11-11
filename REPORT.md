# Hash Cracking Attempt for Variant 5

This repository contains the raw dataset (`Data/data_вар. 5.xlsx`) and a
Python script (`scripts/crack_phone_hashes.py`) that automates several brute
force experiments over common hash algorithms and salt-placement patterns.
Because third-party dependencies are unavailable in the execution environment,
the script includes a minimal XLSX parser and uses the standard `hashlib`
implementations exclusively.

## What the script does

* reads the workbook manually via `zipfile` and `xml.etree.ElementTree`;
* extracts the known `(hash, phone)` pairs from column `C` (five numbers are
  provided in the dataset);
* iterates through combinations of:
  * hash algorithms: `md5`, `sha1`, `sha256`, `blake2s` (16-byte digest);
  * salt placement patterns: `salt + phone`, `phone + salt`, and
    `salt + phone + salt`;
  * salt alphabets/ranges (`digits`, `lowercase`, alphanumeric, small set of
    printable characters) with lengths up to four characters.
* If a combination matches all known pairs the tool would decode the full
  dataset; otherwise it reports the number of candidates tested for each
  combination and suggests expanding the search space.

## Current result

Running the script against the provided dataset did not locate a matching
combination inside the default search space. Below is an excerpt from the run
(see the console logs for the complete output):

```
Loaded 5 known pairs for calibration.
Tried 11,110 candidates for md5 / salt+phone within digits (1-4) without success.
...
Tried 4,422 candidates for blake2s16 / salt+phone+salt within printable (1-2) without success.
No combination found in the current search space.
```

The code is structured so that new hash algorithms, patterns, or extended salt
spaces can be added quickly if more information about the hashing scheme
becomes available.

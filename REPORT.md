# Hashcat Workflow for Variant 5

This repository now ships a helper script, `scripts/crack_phone_hashes.py`, that
prepares the provided dataset (`Data/data_вар. 5.xlsx`) for use with
[hashcat](https://hashcat.net/hashcat/) and automates the typical cracking
workflow.

## What the script does

* parses the XLSX file without external dependencies to extract the hashed
  values (column **A**) and the five known phone numbers (column **C**);
* generates temporary hash lists for the calibration set and the full dataset;
* optionally enumerates candidate salts from configurable search spaces;
* invokes `hashcat` with a user-specified hash type, mask, and salt pattern;
* validates that the selected parameters successfully recover every known
  plaintext sample before attacking the full dataset;
* writes a `hash -> phone` mapping for every recovered entry.

## Example usage

```bash
# Attempt an MD5 + salt-prefix crack using numeric salts up to four characters.
python3 scripts/crack_phone_hashes.py Data/'data_вар. 5.xlsx' \
  --hash-type 0 \
  --pattern salt+phone \
  --salt-space digits1-4 \
  --mask 8?d?d?d?d?d?d?d?d?d?d \
  --extra-arg --force
```

Adjust `--hash-type` to the desired hashcat mode (e.g., `100` for SHA1,
`1400` for SHA256), expand `--salt-space` as needed, and swap the pattern to
`phone+salt` or `phone` for other arrangements.

## Notes

* Hashcat is not bundled with this repository. Install it separately and ensure
  the `hashcat` binary is reachable via `$PATH` or point the script at a custom
  location with `--hashcat /path/to/hashcat`.
* If the environment lacks GPU support, pass `--extra-arg --opencl-device-types 1`
  (CPU only) or any other options suitable for your setup.
* The script exits early when the known calibration samples are not recovered,
  preventing time-consuming attacks with incorrect parameters.
* Expand the salt search space or adjust the mask to evaluate how salt length,
  salt alphabet, and hash type impact cracking performance, as required by the
  lab assignment.

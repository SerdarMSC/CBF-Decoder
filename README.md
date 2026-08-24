# Mercedes / Xentry CBF Parser

A Python-based reverse-engineering and inspection tool for Mercedes-Benz Xentry CBF diagnostic files.

> **Status:** Experimental / reverse-engineering project  
> **Important:** CBF is an undocumented binary format with multiple variants and generations. This project deliberately distinguishes observed binary data from inferred diagnostic mappings.

## Features

The parser can:

- Read Mercedes/Xentry `.CBF` binary files.
- Scan a single CBF or an entire directory recursively.
- Extract printable ASCII strings.
- Extract UTF-16LE strings used by some CBF variants.
- Detect likely CBF object names such as:
  - `DT_`
  - `PREP_`
  - `PRES_`
  - `ADJ_`
  - `FN_`
  - `DJ_`
  - `TAB_`
  - `ENUM_`
  - `IO...`
- Identify interesting diagnostic parameters such as:
  - Particle Filter / DPF
  - Soot
  - Ash
  - Regeneration
  - Injector / Injection
  - Cylinder
  - Coolant temperature
  - Pressure
  - Adaptation
  - Reset
  - Learning
  - Torque converter / clutch / gearbox
- Record binary offsets for discovered objects and strings.
- Save hexadecimal context around interesting objects.
- Detect candidate diagnostic service bytes, including:
  - `0x21` — KWP local identifier
  - `0x22` — UDS data identifier
  - `0x2E` — UDS write data
  - `0x2F` — UDS input/output control
  - `0x31` — UDS routine control
  - `0x3B` — KWP write local identifier
- Produce JSON and CSV reports.
- Process large collections of CBF files automatically.

## Project Structure

```text
.
├── cbf_parser.py
├── build-cbf-parser.yml
├── README.md
└── cbf/
    ├── CRD.CBF
    ├── EGS53.CBF
    ├── ESP.CBF
    └── ...
```

CBF files do **not** need to be committed to the repository if they are private or copyrighted. They can be supplied to the executable locally.

## Requirements

For running from source:

- Python 3.10+
- No third-party Python packages are required.

For building the Windows executable:

- Python 3.10+
- PyInstaller

## Running the Parser

### Single CBF

```bash
python cbf_parser.py CRD.CBF
```

Default output:

```text
decoded/
```

### Directory

```bash
python cbf_parser.py ./cbf --out ./decoded
```

The directory is scanned recursively for files ending in `.cbf` (case-insensitive).

### Minimum String Length

The default minimum printable-string length is 4.

It can be changed:

```bash
python cbf_parser.py ./cbf --out ./decoded --min-string 3
```

## Output

For a file such as:

```text
CRD.CBF
```

the parser creates:

```text
decoded/
├── CRD.json
├── CRD_objects.csv
├── CRD_strings.csv
├── CRD_diagnostic_candidates.csv
└── cbf_summary.json
```

### JSON

`CRD.json` contains:

- Parser information
- File size
- SHA-256
- Extracted strings
- Interesting objects
- Object offsets
- Object categories
- Nearby binary context
- Diagnostic candidates
- Candidate object relationships

### Objects CSV

`CRD_objects.csv` contains columns such as:

```text
name
offset
end
category
description
parameter_score
context_hex
```

### Strings CSV

`CRD_strings.csv` contains:

```text
offset
end
encoding
text
interesting
```

### Diagnostic Candidates CSV

`CRD_diagnostic_candidates.csv` contains:

```text
offset
service
service_name
candidate_id
id_width
confidence
reason
bytes_hex
nearby_objects
```

These entries are **candidates**, not automatically confirmed diagnostic commands.

## Windows EXE

The included GitHub Actions workflow builds a standalone Windows executable with PyInstaller.

### Local Build

Install PyInstaller:

```bash
python -m pip install pyinstaller
```

Build:

```bash
pyinstaller --onefile --clean --name CBFParser cbf_parser.py
```

The executable will be:

```text
dist/CBFParser.exe
```

### Run the EXE

```cmd
CBFParser.exe C:\MercedesCBF --out C:\Decoded
```

No Python installation is required on the machine where the generated standalone EXE is executed.

## GitHub Actions

The repository includes:

```text
build-cbf-parser.yml
```

The workflow:

1. Checks out the repository.
2. Installs Python.
3. Installs PyInstaller.
4. Performs a Python syntax check.
5. Builds `CBFParser.exe`.
6. Runs `CBFParser.exe --help`.
7. Uploads the executable as a GitHub Actions artifact.

Run it from:

```text
GitHub
→ Actions
→ Build CBF Parser
→ Run workflow
```

The resulting artifact is:

```text
CBFParser-Windows
```

containing:

```text
CBFParser.exe
```

## How the Parser Treats CBF Data

CBF is not treated as a simple text file.

A useful conceptual model is:

```text
CBF
│
├── Binary metadata
├── Object definitions
├── Diagnostic services
├── Data objects
├── Preparation / conversion information
├── Presentation information
├── Adjustment / job definitions
├── Tables / enumerations
└── Text resources
```

The long-term objective is to resolve relationships such as:

```text
DT_xxx
   │
   ├── PREP_xxx
   │
   ├── PRES_xxx
   │
   └── diagnostic service / identifier
```

and eventually produce a machine-readable diagnostic definition:

```text
ECU
Protocol
Service
LID / DID
Name
Description
Request
Response
Byte offset
Bit offset
Length
Signed / unsigned
Endian
Factor
Offset
Unit
Enumeration
```

## Important: Candidate vs Confirmed Data

Finding:

```text
21 64
```

inside a CBF does **not** automatically prove that:

```text
21 64
```

is the correct diagnostic request for a specific ECU.

Likewise, finding:

```text
DT_IO64_mSot_Particle_Filter_Soot_Load
```

proves that the corresponding parameter name exists in the CBF, but does not by itself prove the complete response byte layout or scaling formula.

The parser therefore reports such information as candidates until the binary object relationships and, where possible, real ECU responses confirm them.

## Reverse-Engineering Roadmap

The current parser is a foundation rather than a finished CBF specification.

The next stages are:

### 1. Binary Object Structure

Determine the common object header:

```text
offset
object type
object length
object ID
references
payload
```

across multiple CBF generations.

### 2. Object References

Automatically resolve relationships between:

```text
DT_
PREP_
PRES_
ADJ_
FN_
DJ_
IO_
```

objects.

### 3. Diagnostic Mapping

Resolve:

```text
Protocol
→ Service
→ LID / DID
→ Response
→ Data object
```

### 4. Data Conversion

Decode:

```text
bit position
byte position
length
endianness
signedness
factor
offset
unit
min/max
enumeration
```

### 5. Complete Diagnostic Database

Generate a unified database such as:

```text
cbf_database.json
```

with all supported ECUs and their diagnostic parameters.

This database could then be consumed by an Android/Windows diagnostic application without requiring the CBF files at runtime.

## Safety / Reliability

This project is intended for **diagnostic data extraction and reverse engineering**.

Reading diagnostic information is different from writing or executing ECU functions.

Particular care is required before implementing:

- ECU reset
- adaptation reset
- actuator activation
- coding
- programming
- security access
- write-data services
- routine controls

A byte sequence identified by the parser should not be sent to a vehicle ECU solely because it appears in a CBF. It should first be validated against the relevant CBF object definitions and, preferably, a controlled diagnostic environment.

## License / CBF Files

The parser source code can be distributed independently of Mercedes/Xentry CBF files.

CBF files may contain proprietary diagnostic information and should only be distributed or used where the user has the appropriate rights.

## Author / Project

Mercedes CBF reverse-engineering and diagnostic parser project.

The project is intended to make large collections of Mercedes diagnostic descriptions searchable, structured, and usable by independent diagnostic software.

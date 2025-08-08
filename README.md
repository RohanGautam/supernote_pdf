# supernote-pdf

[![Crates.io](https://img.shields.io/crates/v/supernote-pdf.svg)](https://crates.io/crates/supernote-pdf)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A blazing-fast CLI tool for converting Supernote `.note` files to PDF, optimized for archival and backup.

This tool is designed for one thing: converting Supernote `.note` files to PDF at maximum speed. It leverages parallel processing and custom PDF generation logic to handle large collections of notes in seconds, not minutes.

## ✨ Features

- **🚀 Blazing Fast:** Asynchronously decodes pages and processes entire folders in parallel. See [Benchmarks](#-benchmarks) for details.
- **📂 Directory Conversion:** Converts an entire folder of `.note` files, perfectly preserving the original directory structure.
- **💻 Simple & Powerful CLI:** A straightforward command-line interface for single-file or batch conversions.
- **🔧 Optimized for Archival:** Creates PDFs with embedded images, keeping file sizes small and conversion times low for densely written notes.
- **✅ Robust:** Includes safety checks to prevent accidental data loss (e.g., won't overwrite an existing output directory).

Here’s how directory conversion works:

```
Input Directory         Output Directory
-----------------       ------------------
notes/                  notes_pdf/
├── Meeting.note  ====> ├── Meeting.pdf
└── project/            └── project/
    ├── Ideas.note      ====> ├── Ideas.pdf
    └── Draft.note          └── Draft.pdf
```

## Conception

Several key design decisions were made to optimize for the primary goal of fast, reliable backups:

- **A5X Support:** The tool is tested and optimized for the Supernote A5X with the latest firmware (that's what I have and can test!). Support for other devices is on the [Roadmap](#-roadmap).
- **Archival Focus:** This conversion is for backup and viewing. It does not (yet) support interactive PDF features like hyperlinks or tags from the original note.
- **Raster over Vector:** The converter embeds page images (raster graphics) directly into the PDF. While vector graphics are infinitely scalable, this approach was chosen because:
  - It keeps file sizes significantly smaller for notes with a lot of writing.
  - It drastically reduces the compute and storage costs associated with complex vector conversions.

## 📦 Installation

### From Crates.io (Recommended)

Ensure you have the Rust toolchain installed. Then, you can install `supernote-pdf` directly from Crates.io using `cargo`:

```bash
cargo install supernote-pdf
```

### From Source

1.  Clone the repository:
    ```bash
    git clone https://github.com/your-username/supernote-pdf.git
    cd supernote-pdf
    ```
2.  Build and run the project:
    ```bash
    cargo run --release -- -i <input-path> -o <output-path>
    ```

## 🚀 Usage

The CLI is simple, requiring an input path and an output path.

```bash
supernote-pdf -i <input-path> -o <output-path>
```

### Example 1: Convert a Single File

To convert a single `.note` file to a `.pdf` file:

```bash
supernote-pdf -i "My Notes/Meeting Agenda.note" -o "Archive/Meeting Agenda.pdf"
```

### Example 2: Convert an Entire Directory

To convert your entire `Note` folder (copied from your Supernote) into a new `Note_PDFs` directory:

```bash
supernote-pdf -i path/to/your/Note_folder -o path/to/your/Note_PDFs
```

The tool will scan for all `.note` files in the input directory, recreate the folder structure in the output directory, and convert every file.

**Note:** For safety, the output directory must not already exist. This prevents you from accidentally overwriting previous backups.

## 📊 Benchmarks

`supernote-pdf` is significantly faster than available tools, making it ideal for large and frequent backups.

### Single File Conversion

Test converting a 30-page, ~50MB `.note` file:

| Tool                            | Time      | Performance     |
| ------------------------------- | --------- | --------------- |
| `supernote-tool`                | `18.6 s`  | Baseline        |
| **`supernote-pdf` (this tool)** | `~600 ms` | **~30x Faster** |

### Full Directory Conversion

Test converting a local copy of my Supernote's `Note` folder:

- **Input:** `~800 MB` directory of `.note` files
- **Time Taken:** `~13 s`
- **Output:** `~84 MB` directory of `.pdf` files

---

_Testing environment for the benchmarks above was on my Thinkpad X1 Extreme Gen2, Core i7 9th Gen. Your results may vary._
_`supernote-tool` was run using `uvx --from supernotelib supernote-tool convert -t pdf ...` several times._

## 🗺️ Roadmap

- [ ] Vector graphic support as an optional feature.
- [ ] Support for more Supernote device formats (A6X, etc.). See [jya-dev/supernote-tool](https://github.com/jya-dev/supernote-tool) for a project that supports more formats.
- [ ] A web-based interface (WASM) for drag-and-drop conversion.
- [ ] Support for PDF hyperlinks and tags.
- [ ] CI pipeline

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/RohanGautam/supernote_pdf/issues).

## 🙏 Acknowledgements

- This tool stands on the shoulders of giants. A big thank you to the developers of [**supernote-tool**](https://github.com/jya-dev/supernote-tool/tree/master), whose work provided the initial understanding of the `.note` file format and served as a valuable benchmark.

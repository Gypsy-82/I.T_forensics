# Forensic Toolkit v1.0

A sandboxed, offline forensic analysis tool for detecting file anomalies and performing deep file forensics.

## Features

- **Single File Analysis** - Full forensic breakdown of any file
- **Comparison Analysis** - Anomaly detection between 2+ files
- **Auto-Setup** - Creates its own virtual environment and installs dependencies on first run
- **Sandboxed** - Files are analyzed in an isolated environment; originals are never modified
- **Offline** - Network access is blocked during analysis; no data leaves your machine
- **No Artifacts** - Reports are only saved to your Desktop and only when you agree

## Supported File Types

| Category | Formats |
|----------|---------|
| Video | MP4, MOV, AVI, MKV, WebM, WMV, FLV, 3GP |
| Image | JPEG, PNG, GIF, BMP, TIFF, WebP |
| Audio | MP3, WAV, FLAC, OGG, AAC, WMA, M4A |
| Document | PDF, DOCX, XLSX, PPTX, TXT, CSV, JSON, XML |

## Requirements

- Python 3.6 or higher
- `mediainfo` (optional, for enhanced video/audio analysis)
  - Ubuntu/Debian: `sudo apt install mediainfo`
  - Fedora: `sudo dnf install mediainfo`
  - macOS: `brew install mediainfo`

## Usage

```bash
python3 forensic_toolkit.py
On first run, the script will automatically:

Create a virtual environment
Install all required Python libraries
Re-launch inside the virtual environment
After setup, follow the on-screen prompts.

Analysis Capabilities
Hashing & Integrity
MD5, SHA-1, SHA-256, SHA-512 checksums
Partial hashes (head/tail) for quick comparison
File Structure
Magic byte detection (true file type identification)
MP4/MOV container atom/box parsing
ZIP structure analysis for Office documents
Appended/hidden data detection (JPEG, PNG, PDF)
Shannon entropy and byte distribution analysis
Video Analysis
Frame-by-frame sampling and intensity analysis
Codec, resolution, FPS, duration extraction
Multiple stream detection
Container padding detection
Data rate anomaly detection
Image Analysis
EXIF metadata extraction (including GPS/location data)
Pixel-level comparison between images
Compression ratio analysis
JPEG quality estimation
Color distribution statistics
Audio Analysis
Waveform RMS level and amplitude analysis
ID3 tag extraction
Bitrate and encoding analysis
Silence and clipping detection
Embedded album art detection
Document Analysis
PDF: page analysis, JavaScript detection, embedded objects, encryption status
DOCX: paragraph/table counts, VBA macro detection, embedded images
XLSX: sheet analysis, macro detection
Text: encoding detection, line ending analysis, null byte detection
Comparison Mode
Binary-level file comparison
Hash mismatch identification
Size anomaly detection (including WhatsApp-style duplication)
Metadata field-by-field differencing
Content-level comparison (frames, pixels, waveforms)
Automated verdict generation
Security
All analysis runs in a sandboxed temporary directory
Original files are never modified (read-only copies)
Network access is disabled during analysis
No data is written to disk unless you explicitly approve
Reports go to Desktop only — nowhere else
Sandbox is automatically cleaned up after each analysis

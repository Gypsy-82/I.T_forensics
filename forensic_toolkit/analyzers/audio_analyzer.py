"""
Audio Analyzer
===============
Deep forensic analysis of audio files.
Supports: MP3, WAV, FLAC, OGG, AAC, WMA, M4A

Uses: mutagen, wave (native)
"""

import os
import wave
import struct

from core.hasher import compute_hashes, compute_partial_hashes
from core.file_inspector import (
    get_file_info,
    detect_file_type,
    detect_appended_data,
    analyze_byte_distribution,
)


def analyze_audio(file_path):
    """Perform full forensic analysis on an audio file."""
    report = {
        "analysis_type": "Audio Forensic Analysis",
        "file_info": {},
        "file_type_detection": {},
        "hashes": {},
        "partial_hashes": {},
        "audio_properties": {},
        "metadata_tags": {},
        "waveform_analysis": {},
        "appended_data": [],
        "byte_distribution": {},
        "anomalies": [],
    }

    # Basic analysis
    report["file_info"] = get_file_info(file_path)
    report["file_type_detection"] = detect_file_type(file_path)
    report["hashes"] = compute_hashes(file_path)
    report["partial_hashes"] = compute_partial_hashes(file_path)
    report["byte_distribution"] = analyze_byte_distribution(file_path)
    report["appended_data"] = detect_appended_data(file_path)

    if report["appended_data"]:
        for item in report["appended_data"]:
            report["anomalies"].append(
                f"APPENDED DATA: {item['type']} - {item['extra_human']} extra"
            )

    # WAV native analysis
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".wav":
        _analyze_wav(file_path, report)

    # Mutagen analysis (works for most audio formats)
    try:
        import mutagen
        from mutagen.mp3 import MP3
        from mutagen.flac import FLAC
        from mutagen.oggvorbis import OggVorbis
        from mutagen.mp4 import MP4

        audio = mutagen.File(file_path)
        if audio is not None:
            # General properties
            props = {}
            if hasattr(audio.info, "length"):
                props["duration_seconds"] = round(audio.info.length, 3)
            if hasattr(audio.info, "bitrate"):
                props["bitrate"] = audio.info.bitrate
                props["bitrate_human"] = f"{audio.info.bitrate // 1000} kbps"
            if hasattr(audio.info, "sample_rate"):
                props["sample_rate"] = audio.info.sample_rate
            if hasattr(audio.info, "channels"):
                props["channels"] = audio.info.channels
            if hasattr(audio.info, "bits_per_sample"):
                props["bits_per_sample"] = audio.info.bits_per_sample
            if hasattr(audio.info, "encoder_info"):
                props["encoder_info"] = audio.info.encoder_info
            if hasattr(audio.info, "bitrate_mode"):
                props["bitrate_mode"] = str(audio.info.bitrate_mode)
            if hasattr(audio.info, "codec"):
                props["codec"] = audio.info.codec

            props["mutagen_type"] = type(audio).__name__

            report["audio_properties"].update(props)

            # Metadata tags
            tags = {}
            if audio.tags:
                for key, value in audio.tags.items():
                    try:
                        tags[str(key)] = str(value)
                    except Exception:
                        tags[str(key)] = "<unreadable>"

            report["metadata_tags"] = tags if tags else {"note": "No tags found"}

            # MP3-specific analysis
            if isinstance(audio, MP3):
                _analyze_mp3_specific(file_path, audio, report)

            # Check for unusually large metadata
            if audio.tags:
                tag_str = str(audio.tags)
                if len(tag_str) > 10000:
                    report["anomalies"].append(
                        f"Unusually large metadata: {len(tag_str)} bytes"
                    )

            # Duration vs file size check
            if (
                "duration_seconds" in props
                and "bitrate" in props
                and props["duration_seconds"] > 0
                and props["bitrate"] > 0
            ):
                expected_size = (
                    props["bitrate"] * props["duration_seconds"]
                ) / 8
                actual_size = report["file_info"]["file_size_bytes"]
                size_ratio = actual_size / expected_size if expected_size > 0 else 0

                report["audio_properties"]["expected_size_bytes"] = int(
                    expected_size
                )
                report["audio_properties"]["size_ratio"] = round(size_ratio, 3)

                if size_ratio > 1.5:
                    report["anomalies"].append(
                        f"File is {size_ratio:.1f}x larger than expected "
                        f"for its bitrate/duration - possible embedded data"
                    )
                elif size_ratio < 0.5:
                    report["anomalies"].append(
                        f"File is {size_ratio:.1f}x smaller than expected "
                        f"- possible truncation or VBR encoding"
                    )

        else:
            report["audio_properties"]["error"] = (
                "Mutagen could not identify the audio format"
            )

    except ImportError:
        report["audio_properties"]["mutagen_error"] = "mutagen not available"
    except Exception as e:
        report["audio_properties"]["error"] = str(e)

    return report


def _analyze_wav(file_path, report):
    """Native WAV file analysis using the wave module."""
    try:
        with wave.open(file_path, "rb") as wav:
            report["audio_properties"].update({
                "channels": wav.getnchannels(),
                "sample_width_bytes": wav.getsampwidth(),
                "bits_per_sample": wav.getsampwidth() * 8,
                "sample_rate": wav.getframerate(),
                "frame_count": wav.getnframes(),
                "compression_type": wav.getcomptype(),
                "compression_name": wav.getcompname(),
                "duration_seconds": round(
                    wav.getnframes() / wav.getframerate(), 3
                ) if wav.getframerate() > 0 else 0,
            })

            # Read audio data for waveform analysis
            try:
                import numpy as np

                wav.rewind()
                frames = wav.readframes(min(wav.getnframes(), 44100 * 5))
                sample_width = wav.getsampwidth()

                if sample_width == 2:
                    dtype = np.int16
                elif sample_width == 4:
                    dtype = np.int32
                else:
                    dtype = np.uint8

                audio_data = np.frombuffer(frames, dtype=dtype)
                if len(audio_data) > 0:
                    report["waveform_analysis"] = {
                        "samples_analyzed": len(audio_data),
                        "mean_amplitude": round(float(np.mean(np.abs(audio_data))), 2),
                        "max_amplitude": int(np.max(np.abs(audio_data))),
                        "rms_level": round(
                            float(np.sqrt(np.mean(audio_data.astype(float) ** 2))),
                            2,
                        ),
                        "is_silent": bool(np.max(np.abs(audio_data)) < 10),
                        "clipping_detected": bool(
                            np.max(np.abs(audio_data))
                            >= (2 ** (sample_width * 8 - 1) - 1)
                        ),
                    }

                    if report["waveform_analysis"]["is_silent"]:
                        report["anomalies"].append(
                            "Audio appears to be silent"
                        )
                    if report["waveform_analysis"]["clipping_detected"]:
                        report["anomalies"].append(
                            "Audio clipping detected (samples at max amplitude)"
                        )

            except ImportError:
                report["waveform_analysis"] = {"error": "numpy not available"}

    except wave.Error as e:
        report["audio_properties"]["wav_error"] = str(e)
    except Exception as e:
        report["audio_properties"]["wav_error"] = str(e)


def _analyze_mp3_specific(file_path, audio, report):
    """MP3-specific analysis: ID3 tags, frame sync, padding."""
    # Check for ID3v1 vs ID3v2
    id3_info = {}
    if hasattr(audio, "tags") and audio.tags:
        id3_info["tag_version"] = str(type(audio.tags).__name__)

    # Check for embedded album art (can inflate file size)
    if audio.tags:
        for key in audio.tags:
            if key.startswith("APIC"):
                art = audio.tags[key]
                id3_info["embedded_album_art"] = {
                    "mime": getattr(art, "mime", "unknown"),
                    "size_bytes": len(getattr(art, "data", b"")),
                }
                if len(getattr(art, "data", b"")) > 500000:
                    report["anomalies"].append(
                        f"Large embedded album art: "
                        f"{len(art.data) // 1024} KB"
                    )

    if id3_info:
        report["audio_properties"]["id3_info"] = id3_info

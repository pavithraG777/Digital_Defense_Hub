package deepfakeforensics

import (
	"bytes"
	"strings"
)

var (
	pngSignature = []byte{
		0x89, 0x50, 0x4e, 0x47,
		0x0d, 0x0a, 0x1a, 0x0a,
	}
	ebmlSignature = []byte{
		0x1a, 0x45, 0xdf, 0xa3,
	}
)

// matchesExpectedMediaSignature prevents an attacker from
// bypassing media validation by changing only the extension
// or multipart Content-Type.
func matchesExpectedMediaSignature(
	extension string,
	header []byte,
) bool {
	extension = strings.ToLower(
		strings.TrimSpace(extension),
	)

	switch extension {
	case ".jpg", ".jpeg":
		return len(header) >= 3 &&
			header[0] == 0xff &&
			header[1] == 0xd8 &&
			header[2] == 0xff

	case ".png":
		return bytes.HasPrefix(
			header,
			pngSignature,
		)

	case ".webp":
		return isRIFFContainer(
			header,
			"WEBP",
		)

	case ".bmp":
		return bytes.HasPrefix(
			header,
			[]byte("BM"),
		)

	case ".tif", ".tiff":
		return bytes.HasPrefix(
			header,
			[]byte{'I', 'I', 0x2a, 0x00},
		) ||
			bytes.HasPrefix(
				header,
				[]byte{'M', 'M', 0x00, 0x2a},
			)

	case ".mp4", ".mov", ".m4v", ".m4a":
		return len(header) >= 12 &&
			string(header[4:8]) == "ftyp"

	case ".avi":
		return isRIFFContainer(
			header,
			"AVI ",
		)

	case ".mkv", ".webm":
		return bytes.HasPrefix(
			header,
			ebmlSignature,
		)

	case ".wav":
		return isRIFFContainer(
			header,
			"WAVE",
		)

	case ".mp3":
		return bytes.HasPrefix(
			header,
			[]byte("ID3"),
		) || hasMPEGAudioFrameSync(header)

	case ".flac":
		return bytes.HasPrefix(
			header,
			[]byte("fLaC"),
		)

	case ".aac":
		return bytes.HasPrefix(
			header,
			[]byte("ADIF"),
		) || hasAACFrameSync(header)

	case ".ogg":
		return bytes.HasPrefix(
			header,
			[]byte("OggS"),
		)

	case ".pdf":
		return bytes.HasPrefix(
			header,
			[]byte("%PDF-"),
		)

	default:
		return false
	}
}

func hasMPEGAudioFrameSync(
	header []byte,
) bool {
	return len(header) >= 2 &&
		header[0] == 0xff &&
		header[1]&0xe0 == 0xe0
}

func hasAACFrameSync(
	header []byte,
) bool {
	return len(header) >= 2 &&
		header[0] == 0xff &&
		header[1]&0xf6 == 0xf0
}

func isRIFFContainer(
	header []byte,
	containerType string,
) bool {
	return len(header) >= 12 &&
		string(header[:4]) == "RIFF" &&
		string(header[8:12]) == containerType
}

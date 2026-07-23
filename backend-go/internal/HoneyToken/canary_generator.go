package honeytoken

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

var (
	ErrUnsupportedCanaryType = errors.New("unsupported canary file type")
	ErrInvalidCanaryFileName = errors.New("invalid canary file name")
)

type CanaryGenerator struct {
	storageRoot string
}

type canaryGenerationInput struct {
	ID                   uuid.UUID
	OrganizationID       uuid.UUID
	FileName             string
	CanaryType           string
	LinkedHoneytokenCode *string
}

type canaryGenerationResult struct {
	CanaryCode         string
	FileName           string
	FilePath           string
	FileExtension      string
	MimeType           string
	OriginalFileHash   string
	HashAlgorithm      string
	FileSizeBytes      int64
	TrackingIdentifier string
}

func NewCanaryGenerator(
	storageRoot string,
) (*CanaryGenerator, error) {
	storageRoot = strings.TrimSpace(storageRoot)
	if storageRoot == "" {
		return nil, errors.New("canary storage root is required")
	}

	absoluteRoot, err := filepath.Abs(storageRoot)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to resolve canary storage root: %w",
			err,
		)
	}

	absoluteRoot = filepath.Clean(absoluteRoot)

	if err = os.MkdirAll(absoluteRoot, 0750); err != nil {
		return nil, fmt.Errorf(
			"failed to create canary storage root: %w",
			err,
		)
	}

	return &CanaryGenerator{
		storageRoot: absoluteRoot,
	}, nil
}

// Generate creates a valid decoy file and returns its baseline metadata.
func (g *CanaryGenerator) Generate(
	ctx context.Context,
	input canaryGenerationInput,
) (*canaryGenerationResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if input.ID == uuid.Nil {
		return nil, errors.New("canary file ID is required")
	}

	if input.OrganizationID == uuid.Nil {
		return nil, errors.New("organization ID is required")
	}

	if !isSupportedCanaryType(input.CanaryType) {
		return nil, ErrUnsupportedCanaryType
	}

	fileName, fileExtension, mimeType, err :=
		normalizeCanaryFileName(
			input.FileName,
			input.CanaryType,
		)
	if err != nil {
		return nil, err
	}

	trackingIdentifier, err := generateCanaryTrackingIdentifier()
	if err != nil {
		return nil, err
	}

	canaryCode := generateCanaryCode(input.ID)

	content, err := buildCanaryContent(
		input.CanaryType,
		trackingIdentifier,
		input.LinkedHoneytokenCode,
	)
	if err != nil {
		return nil, err
	}

	if err = ctx.Err(); err != nil {
		return nil, err
	}

	directoryPath := filepath.Join(
		g.storageRoot,
		input.OrganizationID.String(),
		input.ID.String(),
	)

	if err = os.MkdirAll(directoryPath, 0750); err != nil {
		return nil, fmt.Errorf(
			"failed to create canary directory: %w",
			err,
		)
	}

	filePath := filepath.Join(directoryPath, fileName)

	if err = g.validateStoragePath(filePath); err != nil {
		return nil, err
	}

	if err = writeCanaryFileAtomically(filePath, content); err != nil {
		return nil, err
	}

	hash := sha256.Sum256(content)
	fileSize := int64(len(content))

	return &canaryGenerationResult{
		CanaryCode:         canaryCode,
		FileName:           fileName,
		FilePath:           filePath,
		FileExtension:      fileExtension,
		MimeType:           mimeType,
		OriginalFileHash:   hex.EncodeToString(hash[:]),
		HashAlgorithm:      CanaryHashAlgorithmSHA256,
		FileSizeBytes:      fileSize,
		TrackingIdentifier: trackingIdentifier,
	}, nil
}

// RemoveGeneratedFile removes a generated staging file after a failed
// database operation. It only permits deletion inside the canary root.
func (g *CanaryGenerator) RemoveGeneratedFile(
	filePath string,
) error {
	if err := g.validateStoragePath(filePath); err != nil {
		return err
	}

	err := os.Remove(filePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf(
			"failed to remove generated canary file: %w",
			err,
		)
	}

	identifierDirectory := filepath.Dir(filePath)

	if identifierDirectory != g.storageRoot {
		_ = os.Remove(identifierDirectory)
	}

	return nil
}

func (g *CanaryGenerator) validateStoragePath(
	filePath string,
) error {
	cleanPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf(
			"failed to resolve canary file path: %w",
			err,
		)
	}

	cleanPath = filepath.Clean(cleanPath)

	relativePath, err := filepath.Rel(
		g.storageRoot,
		cleanPath,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to validate canary file path: %w",
			err,
		)
	}

	if relativePath == ".." ||
		strings.HasPrefix(
			relativePath,
			".."+string(filepath.Separator),
		) {
		return errors.New(
			"canary file path is outside configured storage",
		)
	}

	return nil
}

func normalizeCanaryFileName(
	requestedFileName string,
	canaryType string,
) (string, string, string, error) {
	requestedFileName = strings.TrimSpace(requestedFileName)

	if requestedFileName == "" {
		return "", "", "", ErrInvalidCanaryFileName
	}

	if strings.Contains(requestedFileName, "/") ||
		strings.Contains(requestedFileName, `\`) {
		return "", "", "", ErrInvalidCanaryFileName
	}

	cleanedName := strings.Map(
		func(character rune) rune {
			if unicode.IsControl(character) {
				return -1
			}

			switch character {
			case '<', '>', ':', '"', '/', '\\', '|', '?', '*':
				return '_'
			default:
				return character
			}
		},
		requestedFileName,
	)

	cleanedName = strings.Trim(cleanedName, ". ")
	if cleanedName == "" {
		return "", "", "", ErrInvalidCanaryFileName
	}

	extension, mimeType, err :=
		canaryFileFormat(canaryType)
	if err != nil {
		return "", "", "", err
	}

	currentExtension := filepath.Ext(cleanedName)
	baseName := strings.TrimSuffix(
		cleanedName,
		currentExtension,
	)
	baseName = strings.Trim(baseName, ". ")

	if baseName == "" {
		baseName = "Confidential_Record"
	}

	baseRunes := []rune(baseName)
	if len(baseRunes) > 160 {
		baseName = string(baseRunes[:160])
	}

	if isReservedWindowsFileName(baseName) {
		baseName += "_File"
	}

	return baseName + extension, extension, mimeType, nil
}

func canaryFileFormat(
	canaryType string,
) (string, string, error) {
	switch canaryType {
	case CanaryTypeDocument:
		return ".txt", "text/plain", nil

	case CanaryTypeSpreadsheet:
		return ".csv", "text/csv", nil

	case CanaryTypePDF:
		return ".pdf", "application/pdf", nil

	case CanaryTypeImage:
		return ".png", "image/png", nil

	case CanaryTypeArchive:
		return ".zip", "application/zip", nil

	case CanaryTypeDatabaseBackup:
		return ".sql", "application/sql", nil

	case CanaryTypeConfiguration:
		return ".ini", "text/plain", nil

	case CanaryTypeSourceCode:
		return ".go", "text/x-go", nil

	case CanaryTypeCredentialFile:
		return ".txt", "text/plain", nil

	case CanaryTypeCustom:
		return ".txt", "text/plain", nil

	default:
		return "", "", ErrUnsupportedCanaryType
	}
}

func buildCanaryContent(
	canaryType string,
	trackingIdentifier string,
	linkedHoneytokenCode *string,
) ([]byte, error) {
	switch canaryType {
	case CanaryTypeDocument:
		return buildDocumentCanary(
			trackingIdentifier,
			linkedHoneytokenCode,
		), nil

	case CanaryTypeSpreadsheet:
		return buildSpreadsheetCanary(
			trackingIdentifier,
			linkedHoneytokenCode,
		)

	case CanaryTypePDF:
		return buildPDFCanary(
			trackingIdentifier,
			linkedHoneytokenCode,
		), nil

	case CanaryTypeImage:
		return buildImageCanary(trackingIdentifier)

	case CanaryTypeArchive:
		return buildArchiveCanary(
			trackingIdentifier,
			linkedHoneytokenCode,
		)

	case CanaryTypeDatabaseBackup:
		return buildDatabaseBackupCanary(
			trackingIdentifier,
			linkedHoneytokenCode,
		), nil

	case CanaryTypeConfiguration:
		return buildConfigurationCanary(
			trackingIdentifier,
			linkedHoneytokenCode,
		), nil

	case CanaryTypeSourceCode:
		return buildSourceCodeCanary(
			trackingIdentifier,
			linkedHoneytokenCode,
		), nil

	case CanaryTypeCredentialFile:
		return buildCredentialCanary(
			trackingIdentifier,
			linkedHoneytokenCode,
		), nil

	case CanaryTypeCustom:
		return buildCustomCanary(
			trackingIdentifier,
			linkedHoneytokenCode,
		), nil

	default:
		return nil, ErrUnsupportedCanaryType
	}
}

func buildDocumentCanary(
	trackingIdentifier string,
	linkedHoneytokenCode *string,
) []byte {
	return []byte(fmt.Sprintf(
		`CONFIDENTIAL BUSINESS RECORD

Document Classification: Restricted
Department: Finance and Administration
Reference Number: %s
Generated Date: %s

This document contains internal financial planning information,
employee compensation projections, and administrative records.

%s
Authorized personnel only.
`,
		trackingIdentifier,
		time.Now().UTC().Format("2006-01-02"),
		honeytokenReference(linkedHoneytokenCode),
	))
}

func buildSpreadsheetCanary(
	trackingIdentifier string,
	linkedHoneytokenCode *string,
) ([]byte, error) {
	var buffer bytes.Buffer

	writer := csv.NewWriter(&buffer)

	records := [][]string{
		{
			"Employee ID",
			"Employee Name",
			"Department",
			"Monthly Salary",
			"Account Status",
		},
		{"EMP-1042", "Arun Kumar", "Finance", "78500", "Active"},
		{"EMP-1078", "Priya Raman", "Operations", "64200", "Active"},
		{"EMP-1124", "Karthik S", "Engineering", "91600", "Active"},
		{
			trackingIdentifier,
			"Internal Reference",
			"Administration",
			"0",
			honeytokenReference(linkedHoneytokenCode),
		},
	}

	for _, record := range records {
		if err := writer.Write(record); err != nil {
			return nil, fmt.Errorf(
				"failed to generate canary spreadsheet: %w",
				err,
			)
		}
	}

	writer.Flush()

	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf(
			"failed to finalize canary spreadsheet: %w",
			err,
		)
	}

	return buffer.Bytes(), nil
}

func buildPDFCanary(
	trackingIdentifier string,
	linkedHoneytokenCode *string,
) []byte {
	lines := []string{
		"CONFIDENTIAL FINANCIAL SUMMARY",
		"Internal business document",
		"Reference: " + trackingIdentifier,
		"Fiscal allocation and employee compensation records",
		honeytokenReference(linkedHoneytokenCode),
		"Authorized personnel only",
	}

	var content strings.Builder

	content.WriteString("BT\n/F1 18 Tf\n72 760 Td\n")

	for index, line := range lines {
		if index > 0 {
			content.WriteString("0 -28 Td\n/F1 11 Tf\n")
		}

		content.WriteString("(")
		content.WriteString(escapePDFText(line))
		content.WriteString(") Tj\n")
	}

	content.WriteString("ET")

	stream := content.String()

	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
		fmt.Sprintf(
			"<< /Length %d >>\nstream\n%s\nendstream",
			len(stream),
			stream,
		),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}

	var pdf bytes.Buffer

	pdf.WriteString("%PDF-1.4\n")

	offsets := make([]int, len(objects)+1)

	for index, object := range objects {
		objectNumber := index + 1
		offsets[objectNumber] = pdf.Len()

		fmt.Fprintf(
			&pdf,
			"%d 0 obj\n%s\nendobj\n",
			objectNumber,
			object,
		)
	}

	xrefOffset := pdf.Len()

	fmt.Fprintf(
		&pdf,
		"xref\n0 %d\n",
		len(objects)+1,
	)

	pdf.WriteString("0000000000 65535 f \n")

	for objectNumber := 1; objectNumber <= len(objects); objectNumber++ {
		fmt.Fprintf(
			&pdf,
			"%010d 00000 n \n",
			offsets[objectNumber],
		)
	}

	fmt.Fprintf(
		&pdf,
		"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(objects)+1,
		xrefOffset,
	)

	return pdf.Bytes()
}

func buildImageCanary(
	trackingIdentifier string,
) ([]byte, error) {
	canaryImage := image.NewRGBA(
		image.Rect(0, 0, 800, 450),
	)

	draw.Draw(
		canaryImage,
		canaryImage.Bounds(),
		&image.Uniform{
			C: color.RGBA{
				R: 238,
				G: 241,
				B: 246,
				A: 255,
			},
		},
		image.Point{},
		draw.Src,
	)

	draw.Draw(
		canaryImage,
		image.Rect(50, 45, 750, 105),
		&image.Uniform{
			C: color.RGBA{
				R: 30,
				G: 55,
				B: 90,
				A: 255,
			},
		},
		image.Point{},
		draw.Src,
	)

	for row := 0; row < 6; row++ {
		top := 140 + row*42

		draw.Draw(
			canaryImage,
			image.Rect(80, top, 720, top+22),
			&image.Uniform{
				C: color.RGBA{
					R: uint8(175 + row*8),
					G: uint8(185 + row*7),
					B: uint8(200 + row*5),
					A: 255,
				},
			},
			image.Point{},
			draw.Src,
		)
	}

	trackingBytes := []byte(trackingIdentifier)

	for index, value := range trackingBytes {
		if index >= 700 {
			break
		}

		canaryImage.SetRGBA(
			50+index,
			420,
			color.RGBA{
				R: value,
				G: value ^ 0x5A,
				B: value ^ 0xA5,
				A: 255,
			},
		)
	}

	var buffer bytes.Buffer

	if err := png.Encode(&buffer, canaryImage); err != nil {
		return nil, fmt.Errorf(
			"failed to generate canary image: %w",
			err,
		)
	}

	return buffer.Bytes(), nil
}

func buildArchiveCanary(
	trackingIdentifier string,
	linkedHoneytokenCode *string,
) ([]byte, error) {
	var buffer bytes.Buffer

	archive := zip.NewWriter(&buffer)

	files := map[string]string{
		"Confidential_Readme.txt": fmt.Sprintf(
			"Internal archive\nReference: %s\n%s\n",
			trackingIdentifier,
			honeytokenReference(linkedHoneytokenCode),
		),
		"Financial_Manifest.txt": "Finance records\nPayroll backup\nContract archive\n",
	}

	for fileName, content := range files {
		entry, err := archive.Create(fileName)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to create canary archive entry: %w",
				err,
			)
		}

		if _, err = entry.Write([]byte(content)); err != nil {
			return nil, fmt.Errorf(
				"failed to write canary archive entry: %w",
				err,
			)
		}
	}

	if err := archive.Close(); err != nil {
		return nil, fmt.Errorf(
			"failed to finalize canary archive: %w",
			err,
		)
	}

	return buffer.Bytes(), nil
}

func buildDatabaseBackupCanary(
	trackingIdentifier string,
	linkedHoneytokenCode *string,
) []byte {
	return []byte(fmt.Sprintf(
		`-- Confidential database backup
-- Reference: %s
-- Generated: %s

CREATE TABLE employee_payroll_backup (
    employee_id VARCHAR(50),
    employee_name VARCHAR(150),
    department VARCHAR(100),
    monthly_salary NUMERIC(12,2),
    account_reference VARCHAR(255)
);

INSERT INTO employee_payroll_backup VALUES
('EMP-1042', 'Arun Kumar', 'Finance', 78500.00, '%s'),
('EMP-1078', 'Priya Raman', 'Operations', 64200.00, '%s');
`,
		trackingIdentifier,
		time.Now().UTC().Format(time.RFC3339),
		trackingIdentifier,
		honeytokenReference(linkedHoneytokenCode),
	))
}

func buildConfigurationCanary(
	trackingIdentifier string,
	linkedHoneytokenCode *string,
) []byte {
	return []byte(fmt.Sprintf(
		`[application]
name=Payroll Management System
environment=production
reference=%s

[database]
host=payroll-db.internal
port=5432
username=payroll_service
password=%s

[security]
classification=restricted
`,
		trackingIdentifier,
		honeytokenReference(linkedHoneytokenCode),
	))
}

func buildSourceCodeCanary(
	trackingIdentifier string,
	linkedHoneytokenCode *string,
) []byte {
	return []byte(fmt.Sprintf(
		`package payroll

const internalReference = %q
const serviceCredential = %q

type EmployeePayroll struct {
	EmployeeID    string
	EmployeeName  string
	MonthlySalary float64
}

func LoadConfidentialPayroll() []EmployeePayroll {
	return []EmployeePayroll{
		{
			EmployeeID:    "EMP-1042",
			EmployeeName:  "Arun Kumar",
			MonthlySalary: 78500,
		},
	}
}
`,
		trackingIdentifier,
		honeytokenReference(linkedHoneytokenCode),
	))
}

func buildCredentialCanary(
	trackingIdentifier string,
	linkedHoneytokenCode *string,
) []byte {
	return []byte(fmt.Sprintf(
		`INTERNAL SERVICE CREDENTIALS

Environment: Production
Service: Payroll Management System
Username: payroll_service_admin
Password: %s
Access Reference: %s

Authorized administrators only.
`,
		honeytokenReference(linkedHoneytokenCode),
		trackingIdentifier,
	))
}

func buildCustomCanary(
	trackingIdentifier string,
	linkedHoneytokenCode *string,
) []byte {
	return []byte(fmt.Sprintf(
		`CONFIDENTIAL INTERNAL RECORD

Reference: %s
Security Reference: %s
Classification: Restricted

This file is intended only for authorized organizational personnel.
`,
		trackingIdentifier,
		honeytokenReference(linkedHoneytokenCode),
	))
}

func generateCanaryTrackingIdentifier() (string, error) {
	randomBytes := make([]byte, 24)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf(
			"failed to generate canary tracking identifier: %w",
			err,
		)
	}

	return "REF-" + strings.ToUpper(
		hex.EncodeToString(randomBytes),
	), nil
}

func generateCanaryCode(
	canaryID uuid.UUID,
) string {
	identifier := strings.ReplaceAll(
		canaryID.String(),
		"-",
		"",
	)

	return "CNY-" + strings.ToUpper(identifier)
}

func honeytokenReference(
	honeytokenCode *string,
) string {
	if honeytokenCode == nil ||
		strings.TrimSpace(*honeytokenCode) == "" {
		return "INTERNAL-ACCESS-RESTRICTED"
	}

	return strings.TrimSpace(*honeytokenCode)
}

func escapePDFText(
	value string,
) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "(", `\(`)
	value = strings.ReplaceAll(value, ")", `\)`)

	return value
}

func isSupportedCanaryType(
	canaryType string,
) bool {
	switch canaryType {
	case CanaryTypeDocument,
		CanaryTypeSpreadsheet,
		CanaryTypePDF,
		CanaryTypeImage,
		CanaryTypeArchive,
		CanaryTypeDatabaseBackup,
		CanaryTypeConfiguration,
		CanaryTypeSourceCode,
		CanaryTypeCredentialFile,
		CanaryTypeCustom:
		return true

	default:
		return false
	}
}

func isReservedWindowsFileName(
	fileName string,
) bool {
	upperName := strings.ToUpper(
		strings.TrimSpace(fileName),
	)

	switch upperName {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5",
		"COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
		"LPT6", "LPT7", "LPT8", "LPT9":
		return true

	default:
		return false
	}
}

func writeCanaryFileAtomically(
	filePath string,
	content []byte,
) error {
	if _, err := os.Stat(filePath); err == nil {
		return errors.New("canary file already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf(
			"failed to inspect canary file destination: %w",
			err,
		)
	}

	directoryPath := filepath.Dir(filePath)

	temporaryFile, err := os.CreateTemp(
		directoryPath,
		".ddh-canary-*",
	)
	if err != nil {
		return fmt.Errorf(
			"failed to create temporary canary file: %w",
			err,
		)
	}

	temporaryPath := temporaryFile.Name()
	closed := false

	defer func() {
		if !closed {
			_ = temporaryFile.Close()
		}

		_ = os.Remove(temporaryPath)
	}()

	if err = temporaryFile.Chmod(0600); err != nil {
		return fmt.Errorf(
			"failed to secure temporary canary file: %w",
			err,
		)
	}

	if _, err = temporaryFile.Write(content); err != nil {
		return fmt.Errorf(
			"failed to write canary file: %w",
			err,
		)
	}

	if err = temporaryFile.Sync(); err != nil {
		return fmt.Errorf(
			"failed to synchronize canary file: %w",
			err,
		)
	}

	if err = temporaryFile.Close(); err != nil {
		return fmt.Errorf(
			"failed to close canary file: %w",
			err,
		)
	}

	closed = true

	if err = os.Rename(temporaryPath, filePath); err != nil {
		return fmt.Errorf(
			"failed to finalize canary file: %w",
			err,
		)
	}

	return nil
}

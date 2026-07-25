package preencryption

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
)

// FeaturePolicy contains rule thresholds used while
// extracting pre-encryption behavioural features.
type FeaturePolicy struct {
	MassModificationThreshold int
	RapidRenameThreshold      int
	ExtensionChangeThreshold  int
	DeletionBurstThreshold    int
	HashChangeThreshold       int
	PermissionChangeThreshold int

	HighEventRatePerMinute float64

	HighEntropyThreshold  float64
	EntropyDeltaThreshold float64

	KnownRansomwareExtensions map[string]struct{}
	SuspiciousProcessNames    map[string]struct{}
}

type fileEventEntropyMetadata struct {
	EntropyBefore *float64 `json:"entropy_before"`
	EntropyAfter  *float64 `json:"entropy_after"`
	EntropyDelta  *float64 `json:"entropy_delta"`

	IsHighEntropyWrite bool `json:"is_high_entropy_write"`
}

func DefaultFeaturePolicy() FeaturePolicy {
	return FeaturePolicy{
		MassModificationThreshold: 20,
		RapidRenameThreshold:      10,
		ExtensionChangeThreshold:  5,
		DeletionBurstThreshold:    10,
		HashChangeThreshold:       15,
		PermissionChangeThreshold: 5,

		HighEventRatePerMinute: 30,

		HighEntropyThreshold:  7.2,
		EntropyDeltaThreshold: 1.5,

		KnownRansomwareExtensions: map[string]struct{}{
			".akira":     {},
			".alphv":     {},
			".blackcat":  {},
			".clop":      {},
			".conti":     {},
			".crypt":     {},
			".crypto":    {},
			".enc":       {},
			".encrypted": {},
			".lockbit":   {},
			".locked":    {},
			".locky":     {},
			".ryk":       {},
			".ryuk":      {},
			".wannacry":  {},
			".wncry":     {},
		},

		SuspiciousProcessNames: map[string]struct{}{
			"bcdedit.exe":    {},
			"cipher.exe":     {},
			"powershell.exe": {},
			"pwsh.exe":       {},
			"vssadmin.exe":   {},
			"wbadmin.exe":    {},
			"wevtutil.exe":   {},
			"wmic.exe":       {},
		},
	}
}

func ExtractDetectionFeatures(
	window DetectionWindow,
	policy FeaturePolicy,
) (DetectionFeatures, error) {
	var features DetectionFeatures

	if window.OrganizationID == [16]byte{} {
		return features, errors.New(
			"organization ID is required",
		)
	}

	if len(window.Events) == 0 {
		return features, errors.New(
			"detection window must contain file events",
		)
	}

	policy = normalizeFeaturePolicy(policy)

	uniqueFiles := make(
		map[string]struct{},
	)

	uniqueExtensions := make(
		map[string]struct{},
	)

	uniqueProcesses := make(
		map[string]struct{},
	)

	entropyBeforeValues := make(
		[]float64,
		0,
	)

	entropyAfterValues := make(
		[]float64,
		0,
	)

	entropyDeltaValues := make(
		[]float64,
		0,
	)

	windowStartedAt :=
		window.Events[0].OccurredAt.UTC()

	windowEndedAt := windowStartedAt

	fileChangeCount := 0

	for _, event := range window.Events {
		eventTime := event.OccurredAt.UTC()

		if eventTime.Before(windowStartedAt) {
			windowStartedAt = eventTime
		}

		if eventTime.After(windowEndedAt) {
			windowEndedAt = eventTime
		}

		features.TotalEventCount++

		fileKey := strings.ToLower(
			strings.TrimSpace(
				event.FilePath,
			),
		)

		if fileKey != "" {
			uniqueFiles[fileKey] =
				struct{}{}
		}

		extension := normalizeFileExtension(
			event.FileExtension,
		)

		if extension != "" {
			uniqueExtensions[extension] =
				struct{}{}
		}

		processKey := buildProcessKey(
			event,
		)

		if processKey != "" {
			uniqueProcesses[processKey] =
				struct{}{}
		}

		eventType := NormalizeConstant(
			event.EventType,
		)

		switch eventType {
		case EventTypeCreated:
			features.CreatedEventCount++

		case EventTypeModified:
			features.ModifiedEventCount++

		case EventTypeRenamed:
			features.RenamedEventCount++

		case EventTypeExtensionChanged:
			features.ExtensionChangedEventCount++

		case EventTypeDeleted:
			features.DeletedEventCount++

		case EventTypeHashChanged:
			features.HashChangedEventCount++

		case EventTypePermissionChanged:
			features.PermissionChangedEventCount++

		case EventTypeEncrypted:
			features.EncryptedEventCount++

		case EventTypeMultipleFileChanges:
			features.MultipleFileChangeEventCount++
		}

		if IsFileChangeEventType(eventType) {
			fileChangeCount++
		}

		if event.IsSuspicious {
			features.SuspiciousEventCount++
		}

		sourceType := NormalizeConstant(
			event.SourceType,
		)

		switch sourceType {
		case SourceTypeCanaryFile:
			features.CanaryEventCount++

		case SourceTypeHoneytoken:
			features.HoneytokenEventCount++

		case SourceTypeProtectedFile:
			features.ProtectedFileEventCount++
		}

		if event.ThreatScore >
			features.MaximumExistingThreatScore {
			features.MaximumExistingThreatScore =
				event.ThreatScore
		}

		if isKnownRansomwareExtension(
			extension,
			policy.KnownRansomwareExtensions,
		) {
			features.RansomwareExtensionCount++
		}

		if isSuspiciousProcess(
			event,
			policy.SuspiciousProcessNames,
		) {
			features.SuspiciousProcessCount++
		}

		features.TotalBytesChanged =
			addEventBytesChanged(
				features.TotalBytesChanged,
				event.FileSizeBefore,
				event.FileSizeAfter,
			)

		entropyMetadata :=
			parseFileEventEntropyMetadata(
				event.Metadata,
			)

		if entropyMetadata.EntropyBefore != nil &&
			isValidEntropy(
				*entropyMetadata.EntropyBefore,
			) {
			entropyBeforeValues = append(
				entropyBeforeValues,
				*entropyMetadata.EntropyBefore,
			)
		}

		if entropyMetadata.EntropyAfter != nil &&
			isValidEntropy(
				*entropyMetadata.EntropyAfter,
			) {
			entropyAfterValues = append(
				entropyAfterValues,
				*entropyMetadata.EntropyAfter,
			)
		}

		entropyDelta :=
			resolveEntropyDelta(
				entropyMetadata,
			)

		if entropyDelta != nil {
			entropyDeltaValues = append(
				entropyDeltaValues,
				*entropyDelta,
			)
		}

		if isHighEntropyWrite(
			entropyMetadata,
			entropyDelta,
			policy,
		) {
			features.HighEntropyWriteCount++
		}
	}

	features.UniqueFileCount =
		len(uniqueFiles)

	features.UniqueExtensionCount =
		len(uniqueExtensions)

	features.UniqueProcessCount =
		len(uniqueProcesses)

	windowDuration :=
		windowEndedAt.
			Sub(windowStartedAt).
			Seconds()

	if windowDuration < 0 {
		return features, errors.New(
			"invalid detection event window",
		)
	}

	features.WindowDurationSeconds =
		windowDuration

	rateDurationSeconds := windowDuration

	if rateDurationSeconds < 1 {
		rateDurationSeconds = 1
	}

	features.EventRatePerMinute =
		float64(features.TotalEventCount) /
			rateDurationSeconds *
			60

	features.FileChangeRatePerMinute =
		float64(fileChangeCount) /
			rateDurationSeconds *
			60

	features.ModificationRatio =
		safeRatio(
			features.ModifiedEventCount+
				features.MultipleFileChangeEventCount,
			features.TotalEventCount,
		)

	features.RenameRatio =
		safeRatio(
			features.RenamedEventCount,
			features.TotalEventCount,
		)

	features.ExtensionChangeRatio =
		safeRatio(
			features.ExtensionChangedEventCount,
			features.TotalEventCount,
		)

	features.DeletionRatio =
		safeRatio(
			features.DeletedEventCount,
			features.TotalEventCount,
		)

	features.HashChangeRatio =
		safeRatio(
			features.HashChangedEventCount,
			features.TotalEventCount,
		)

	features.SuspiciousEventRatio =
		safeRatio(
			features.SuspiciousEventCount,
			features.TotalEventCount,
		)

	features.AverageEntropyBefore =
		averageFloatValues(
			entropyBeforeValues,
		)

	features.AverageEntropyAfter =
		averageFloatValues(
			entropyAfterValues,
		)

	features.AverageEntropyDelta =
		averageFloatValues(
			entropyDeltaValues,
		)

	features.HasCanaryTrigger =
		features.CanaryEventCount > 0

	features.HasHoneytokenAccess =
		features.HoneytokenEventCount > 0

	features.HasProtectedFileActivity =
		features.ProtectedFileEventCount > 0

	features.HasRapidFileChanges =
		features.EventRatePerMinute >=
			policy.HighEventRatePerMinute ||
			features.MultipleFileChangeEventCount > 0

	features.HasMassModification =
		features.ModifiedEventCount+
			features.MultipleFileChangeEventCount >=
			policy.MassModificationThreshold

	features.HasRapidRename =
		features.RenamedEventCount >=
			policy.RapidRenameThreshold

	features.HasExtensionChangeBurst =
		features.ExtensionChangedEventCount >=
			policy.ExtensionChangeThreshold

	features.HasDeletionBurst =
		features.DeletedEventCount >=
			policy.DeletionBurstThreshold

	features.HasHashChangeBurst =
		features.HashChangedEventCount >=
			policy.HashChangeThreshold

	features.HasPermissionChangeBurst =
		features.PermissionChangedEventCount >=
			policy.PermissionChangeThreshold

	features.HasHighEntropyWrites =
		features.HighEntropyWriteCount > 0

	features.HasEncryptionActivity =
		features.EncryptedEventCount > 0

	features.HasRansomwareExtension =
		features.RansomwareExtensionCount > 0

	features.HasSuspiciousProcess =
		features.SuspiciousProcessCount > 0

	return features, nil
}

func normalizeFeaturePolicy(
	policy FeaturePolicy,
) FeaturePolicy {
	defaultPolicy :=
		DefaultFeaturePolicy()

	if policy.MassModificationThreshold <= 0 {
		policy.MassModificationThreshold =
			defaultPolicy.MassModificationThreshold
	}

	if policy.RapidRenameThreshold <= 0 {
		policy.RapidRenameThreshold =
			defaultPolicy.RapidRenameThreshold
	}

	if policy.ExtensionChangeThreshold <= 0 {
		policy.ExtensionChangeThreshold =
			defaultPolicy.ExtensionChangeThreshold
	}

	if policy.DeletionBurstThreshold <= 0 {
		policy.DeletionBurstThreshold =
			defaultPolicy.DeletionBurstThreshold
	}

	if policy.HashChangeThreshold <= 0 {
		policy.HashChangeThreshold =
			defaultPolicy.HashChangeThreshold
	}

	if policy.PermissionChangeThreshold <= 0 {
		policy.PermissionChangeThreshold =
			defaultPolicy.PermissionChangeThreshold
	}

	if policy.HighEventRatePerMinute <= 0 {
		policy.HighEventRatePerMinute =
			defaultPolicy.HighEventRatePerMinute
	}

	if policy.HighEntropyThreshold <= 0 {
		policy.HighEntropyThreshold =
			defaultPolicy.HighEntropyThreshold
	}

	if policy.EntropyDeltaThreshold <= 0 {
		policy.EntropyDeltaThreshold =
			defaultPolicy.EntropyDeltaThreshold
	}

	if len(policy.KnownRansomwareExtensions) == 0 {
		policy.KnownRansomwareExtensions =
			defaultPolicy.KnownRansomwareExtensions
	}

	if len(policy.SuspiciousProcessNames) == 0 {
		policy.SuspiciousProcessNames =
			defaultPolicy.SuspiciousProcessNames
	}

	return policy
}

func normalizeFileExtension(
	extension *string,
) string {
	if extension == nil {
		return ""
	}

	normalized := strings.ToLower(
		strings.TrimSpace(
			*extension,
		),
	)

	if normalized == "" {
		return ""
	}

	if !strings.HasPrefix(
		normalized,
		".",
	) {
		normalized = "." + normalized
	}

	return normalized
}

func buildProcessKey(
	event FileEventObservation,
) string {
	if event.ProcessID != nil {
		return "pid:" +
			formatInt64(
				*event.ProcessID,
			)
	}

	if event.ProcessName != nil {
		return "name:" +
			normalizeProcessName(
				*event.ProcessName,
			)
	}

	return ""
}

func formatInt64(
	value int64,
) string {
	const digits = "0123456789"

	if value == 0 {
		return "0"
	}

	if value < 0 {
		return ""
	}

	buffer := make(
		[]byte,
		0,
		20,
	)

	for value > 0 {
		remainder := value % 10

		buffer = append(
			buffer,
			digits[remainder],
		)

		value /= 10
	}

	for left, right := 0, len(buffer)-1; left < right; left, right = left+1, right-1 {
		buffer[left], buffer[right] =
			buffer[right], buffer[left]
	}

	return string(buffer)
}

func normalizeProcessName(
	value string,
) string {
	normalized := strings.ToLower(
		strings.TrimSpace(value),
	)

	normalized = strings.ReplaceAll(
		normalized,
		`\`,
		"/",
	)

	pathParts := strings.Split(
		normalized,
		"/",
	)

	return pathParts[len(pathParts)-1]
}

func isKnownRansomwareExtension(
	extension string,
	knownExtensions map[string]struct{},
) bool {
	if extension == "" {
		return false
	}

	_, exists :=
		knownExtensions[extension]

	return exists
}

func isSuspiciousProcess(
	event FileEventObservation,
	suspiciousProcesses map[string]struct{},
) bool {
	candidates := make(
		[]string,
		0,
		2,
	)

	if event.ProcessName != nil {
		candidates = append(
			candidates,
			normalizeProcessName(
				*event.ProcessName,
			),
		)
	}

	if event.ExecutablePath != nil {
		candidates = append(
			candidates,
			normalizeProcessName(
				*event.ExecutablePath,
			),
		)
	}

	for _, candidate := range candidates {
		if _, exists :=
			suspiciousProcesses[candidate]; exists {
			return true
		}
	}

	return false
}

func addEventBytesChanged(
	currentTotal int64,
	sizeBefore *int64,
	sizeAfter *int64,
) int64 {
	if sizeAfter == nil {
		return currentTotal
	}

	if sizeBefore == nil {
		if *sizeAfter > 0 {
			return safeAddInt64(
				currentTotal,
				*sizeAfter,
			)
		}

		return currentTotal
	}

	difference :=
		*sizeAfter - *sizeBefore

	if difference < 0 {
		difference = -difference
	}

	return safeAddInt64(
		currentTotal,
		difference,
	)
}

func safeAddInt64(
	currentValue int64,
	additionalValue int64,
) int64 {
	if additionalValue <= 0 {
		return currentValue
	}

	maximumInt64 :=
		int64(^uint64(0) >> 1)

	if currentValue >
		maximumInt64-additionalValue {
		return maximumInt64
	}

	return currentValue +
		additionalValue
}

func parseFileEventEntropyMetadata(
	metadata json.RawMessage,
) fileEventEntropyMetadata {
	var entropyMetadata fileEventEntropyMetadata

	if len(metadata) == 0 {
		return entropyMetadata
	}

	if err := json.Unmarshal(
		metadata,
		&entropyMetadata,
	); err != nil {
		return fileEventEntropyMetadata{}
	}

	return entropyMetadata
}

func resolveEntropyDelta(
	metadata fileEventEntropyMetadata,
) *float64 {
	if metadata.EntropyDelta != nil &&
		isValidEntropyDelta(
			*metadata.EntropyDelta,
		) {
		value := *metadata.EntropyDelta
		return &value
	}

	if metadata.EntropyBefore == nil ||
		metadata.EntropyAfter == nil ||
		!isValidEntropy(
			*metadata.EntropyBefore,
		) ||
		!isValidEntropy(
			*metadata.EntropyAfter,
		) {
		return nil
	}

	value :=
		*metadata.EntropyAfter -
			*metadata.EntropyBefore

	return &value
}

func isHighEntropyWrite(
	metadata fileEventEntropyMetadata,
	entropyDelta *float64,
	policy FeaturePolicy,
) bool {
	if metadata.IsHighEntropyWrite {
		return true
	}

	if metadata.EntropyAfter != nil &&
		isValidEntropy(
			*metadata.EntropyAfter,
		) &&
		*metadata.EntropyAfter >=
			policy.HighEntropyThreshold {
		return true
	}

	return entropyDelta != nil &&
		*entropyDelta >=
			policy.EntropyDeltaThreshold
}

func isValidEntropy(
	value float64,
) bool {
	return !math.IsNaN(value) &&
		!math.IsInf(value, 0) &&
		value >= 0 &&
		value <= 8
}

func isValidEntropyDelta(
	value float64,
) bool {
	return !math.IsNaN(value) &&
		!math.IsInf(value, 0) &&
		value >= -8 &&
		value <= 8
}

func safeRatio(
	numerator int,
	denominator int,
) float64 {
	if denominator <= 0 {
		return 0
	}

	return float64(numerator) /
		float64(denominator)
}

func averageFloatValues(
	values []float64,
) *float64 {
	if len(values) == 0 {
		return nil
	}

	total := 0.0

	for _, value := range values {
		total += value
	}

	average :=
		total / float64(len(values))

	return &average
}

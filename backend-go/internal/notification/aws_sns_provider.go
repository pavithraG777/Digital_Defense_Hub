package notification

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sns/types"
)

const awsSNSProviderName = "AWS_SNS"

type AWSSNSProviderConfig struct {
	Region             string
	Profile            string
	SenderID           string
	SMSType            string
	DefaultCountryCode string
	Timeout            time.Duration
}

type awsSNSAPI interface {
	Publish(context.Context, *sns.PublishInput, ...func(*sns.Options)) (*sns.PublishOutput, error)
}

type AWSSNSProvider struct {
	config AWSSNSProviderConfig
	client awsSNSAPI
	mu     sync.Mutex
}

func NewAWSSNSProvider(config AWSSNSProviderConfig) (*AWSSNSProvider, error) {
	config.Region = strings.TrimSpace(config.Region)
	config.Profile = strings.TrimSpace(config.Profile)
	config.SenderID = strings.TrimSpace(config.SenderID)
	config.SMSType = strings.TrimSpace(config.SMSType)
	if config.Region == "" {
		return nil, errors.New("AWS SNS region is required")
	}
	if config.SMSType == "" {
		config.SMSType = "Transactional"
	}
	if !strings.EqualFold(config.SMSType, "Transactional") && !strings.EqualFold(config.SMSType, "Promotional") {
		return nil, errors.New("AWS SNS SMS type must be Transactional or Promotional")
	}
	if config.Timeout <= 0 {
		config.Timeout = 20 * time.Second
	}
	if config.DefaultCountryCode != "" {
		normalized, err := normalizeSMSCountryCode(config.DefaultCountryCode)
		if err != nil {
			return nil, err
		}
		config.DefaultCountryCode = normalized
	}
	// Credential resolution is intentionally deferred until the first delivery.
	// This permits local API startup without an AWS profile while MFA remains
	// fail-closed if SMS delivery cannot be authenticated.
	return &AWSSNSProvider{config: config}, nil
}

func (p *AWSSNSProvider) Name() string    { return awsSNSProviderName }
func (p *AWSSNSProvider) Channel() string { return "SMS" }

func (p *AWSSNSProvider) Send(ctx context.Context, message DeliveryMessage) (*ProviderResult, error) {
	if p == nil {
		return nil, errors.New("AWS SNS provider is unavailable")
	}
	client, err := p.getClient(ctx)
	if err != nil {
		return nil, err
	}
	if err := ValidateDeliveryMessage(message); err != nil {
		return nil, fmt.Errorf("validate SMS delivery message: %w", err)
	}
	if message.Delivery.Channel != p.Channel() || message.Recipient.PhoneNumber == nil {
		return nil, errors.New("AWS SNS SMS recipient is required")
	}
	phone, err := normalizeSMSPhoneNumber(*message.Recipient.PhoneNumber, p.config.DefaultCountryCode)
	if err != nil {
		return nil, err
	}
	attrs := map[string]types.MessageAttributeValue{"AWS.SNS.SMS.SMSType": {DataType: strPtr("String"), StringValue: strPtr(p.config.SMSType)}}
	if p.config.SenderID != "" {
		attrs["AWS.SNS.SMS.SenderID"] = types.MessageAttributeValue{DataType: strPtr("String"), StringValue: strPtr(p.config.SenderID)}
	}
	callCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()
	result, err := client.Publish(callCtx, &sns.PublishInput{PhoneNumber: strPtr(phone), Message: strPtr(buildSMSNotificationMessage(message, defaultSMSMaximumMessageSize)), MessageAttributes: attrs})
	if err != nil {
		return nil, fmt.Errorf("publish AWS SNS SMS: %w", err)
	}
	now := time.Now().UTC()
	id := ""
	if result.MessageId != nil {
		id = *result.MessageId
	}
	return &ProviderResult{ProviderName: p.Name(), ProviderMessageID: &id, Delivered: false, SentAt: &now}, nil
}

func (p *AWSSNSProvider) getClient(ctx context.Context) (awsSNSAPI, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client != nil {
		return p.client, nil
	}
	loadOptions := []func(*awscfg.LoadOptions) error{awscfg.WithRegion(p.config.Region)}
	if p.config.Profile != "" {
		loadOptions = append(loadOptions, awscfg.WithSharedConfigProfile(p.config.Profile))
	}
	awsConfig, err := awscfg.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load AWS SNS configuration: %w", err)
	}
	p.client = sns.NewFromConfig(awsConfig)
	return p.client, nil
}

func strPtr(value string) *string { return &value }

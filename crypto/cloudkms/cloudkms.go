package cloudKMS

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/vlct-io/pkg/crypto"
	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
)

// cloudKMS makes it easy to interact with GCP's Cloud KMS service.
// Assumes you have the "GOOGLE_APPLICATION_CREDENTIALS" environment
// variable setup in your environment with access to the Cloud KMS service.
//
// Authentication documentation: https://cloud.google.com/docs/authentication/getting-started
// Go client library: https://cloud.google.com/kms/docs/reference/libraries#client-libraries-install-go
//
// Remember to create a KeyRing and CryptoKey.
// Documentation: https://cloud.google.com/kms/docs/creating-keys
//
// Cloud KMS pricing: https://cloud.google.com/kms/pricing
//
type cloudKMS struct {
	ProjectID   string
	LocationID  string
	KeyRingID   string
	CryptoKeyID string
}

// validate interface conformity.
var _ crypto.Crypter = cloudKMS{}

// New makes a crypto.Crypter.
func New(projectID, locationID, keyRingID, cryptoKeyID string) crypto.Crypter {
	return cloudKMS{
		ProjectID:   projectID,
		LocationID:  locationID,
		KeyRingID:   keyRingID,
		CryptoKeyID: cryptoKeyID,
	}
}

// Encrypt handles all cloudKMS service operations to successfully encrypt the plainText.
func (kms cloudKMS) Encrypt(plaintext []byte) ([]byte, error) {
	ctx := context.Background()
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	cloudKMSService, err := cloudkms.New(client)
	if err != nil {
		return nil, err
	}
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		kms.ProjectID, kms.LocationID, kms.KeyRingID, kms.CryptoKeyID)

	req := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}
	resp, err := cloudKMSService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(parentName, req).Do()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.Ciphertext)
}

// Decrypt handles all cloudKMS service operations to successfully Decrypt the cypherText.
func (kms cloudKMS) Decrypt(ciphertext []byte) ([]byte, error) {
	ctx := context.Background()
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	cloudKMSService, err := cloudkms.New(client)
	if err != nil {
		return nil, err
	}
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		kms.ProjectID, kms.LocationID, kms.KeyRingID, kms.CryptoKeyID)

	req := &cloudkms.DecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	resp, err := cloudKMSService.Projects.Locations.KeyRings.CryptoKeys.Decrypt(parentName, req).Do()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.Plaintext)
}

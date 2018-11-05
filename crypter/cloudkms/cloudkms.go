package crypter

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/vlct-io/pkg/crypter"

	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
)

// CloudKMS makes it easy to interact with GCP's Cloud KMS service.
//
// CloudKMS assumes you have the "GOOGLE_APPLICATION_CREDENTIALS" environment
// variable setup in your environment with access to the Cloud KMS service.
// Documentation: https://cloud.google.com/docs/authentication/getting-started
//
// Remember to create a KeyRing and CryptoKey following this documentation: https://cloud.google.com/kms/docs/creating-keys
//
type CloudKMS struct {
	ProjectID   string
	LocationID  string
	KeyRingID   string
	CryptoKeyID string
}

// validate interface conformity.
var _ crypter.Crypter = CloudKMS{}

// Encrypt handles all CloudKMS service operations to successfully encrypt the plainText.
func (kms CloudKMS) Encrypt(plaintext []byte) ([]byte, error) {
	ctx := context.Background()
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	cloudkmsService, err := cloudkms.New(client)
	if err != nil {
		return nil, err
	}
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		kms.ProjectID, kms.LocationID, kms.KeyRingID, kms.CryptoKeyID)

	req := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}
	resp, err := cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(parentName, req).Do()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.Ciphertext)
}

// Decrypt handles all CloudKMS service operations to successfully Decrypt the cypherText.
func (kms CloudKMS) Decrypt(ciphertext []byte) ([]byte, error) {
	ctx := context.Background()
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	cloudkmsService, err := cloudkms.New(client)
	if err != nil {
		return nil, err
	}
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		kms.ProjectID, kms.LocationID, kms.KeyRingID, kms.CryptoKeyID)

	req := &cloudkms.DecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	resp, err := cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.Decrypt(parentName, req).Do()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.Plaintext)
}

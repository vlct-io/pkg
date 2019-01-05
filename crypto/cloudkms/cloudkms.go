package cloudKMS

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/pkg/errors"

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
	ProjectID    string
	LocationID   string
	KeyRingID    string
	CryptoKeyID  string
	authedClient *http.Client
}

// validate interface conformity.
var _ crypto.Crypter = cloudKMS{}

// New makes a crypto.Crypter.
func New(projectID, locationID, keyRingID, cryptoKeyID string) crypto.Crypter {
	ctx := context.Background()
	authedClient, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		log.Fatal(err)
	}
	kms := cloudKMS{
		ProjectID:    projectID,
		LocationID:   locationID,
		KeyRingID:    keyRingID,
		CryptoKeyID:  cryptoKeyID,
		authedClient: authedClient,
	}
	log.Println("ensuring keys")
	err = kms.EnsureKeys()
	if err != nil {
		log.Fatal(err)
	}
	return kms
}

func (kms cloudKMS) EnsureKeys() error {
	var err error
	kmsService, err := cloudkms.New(kms.authedClient)
	if err != nil {
		return err
	}
	// The resource name of the key rings.
	resourceName := fmt.Sprintf("projects/%s/locations/%s", kms.ProjectID, kms.LocationID)
	// Do RPC call
	res, err := kmsService.Projects.Locations.KeyRings.List(resourceName).Do()
	if err != nil {
		return errors.Wrap(err, "failed to list key rings")
	}
	// find our keyring, exit when we do
	for _, keyRing := range res.KeyRings {
		if strings.Contains(keyRing.Name, kms.KeyRingID) {
			log.Printf("KeyRing found! %v\n", keyRing.Name)
			return nil
		}
	}
	// we don't have a keyring, let's make one
	log.Println("KeyRing empty, generating...")
	if err := kms.createKeyring(kms.KeyRingID); err != nil {
		log.Println("failed to create keyring:", err)
	}
	if err := kms.createCryptoKey(kms.KeyRingID, kms.CryptoKeyID); err != nil {
		return errors.Wrap(err, "failed to create key")
	}

	return errors.New("keyRing not found! Generate one at: https://console.cloud.google.com/security/kms")
}

// Encrypt handles all cloudKMS service operations to successfully encrypt the plainText.
func (kms cloudKMS) Encrypt(plaintext []byte) ([]byte, error) {
	client := kms.authedClient
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
	client := kms.authedClient
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

func (kms cloudKMS) createKeyring(keyRing string) error {
	client, err := cloudkms.New(kms.authedClient)
	if err != nil {
		return err
	}
	location := kms.LocationID
	parent := fmt.Sprintf("projects/%s/locations/%s", kms.ProjectID, location)

	_, err = client.Projects.Locations.KeyRings.Create(
		parent, &cloudkms.KeyRing{}).KeyRingId(keyRing).Do()
	if err != nil {
		return err
	}
	log.Print("Created key ring.")
	return nil
}

func (kms cloudKMS) createCryptoKey(keyRing, key string) error {
	client, err := cloudkms.New(kms.authedClient)
	if err != nil {
		return err
	}
	location := kms.LocationID
	parent := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", kms.ProjectID, location, keyRing)
	purpose := "ENCRYPT_DECRYPT"
	_, err = client.Projects.Locations.KeyRings.CryptoKeys.Create(
		parent, &cloudkms.CryptoKey{
			Purpose: purpose,
		}).CryptoKeyId(key).Do()
	if err != nil {
		return err
	}
	log.Println("Created crypto key.")

	return nil
}

package cloudKMS

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/vlct-io/pkg/crypto"
	"github.com/vlct-io/pkg/logger"
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
	SigningKeyID string
	authedClient *http.Client
}

// validate interface conformity.
var _ crypto.Crypter = cloudKMS{}
var log = logger.New()

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
		CryptoKeyID:  cryptoKeyID + "_crypto",
		SigningKeyID: cryptoKeyID + "_sign",
		authedClient: authedClient,
	}
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
			log.Printf("Using keyring from %v\n", keyRing.Name)
			return nil
		}
	}
	// we don't have a keyring, let's make one
	log.Println("generating KeyRing...")
	if err := kms.createKeyring(kms.KeyRingID); err != nil {
		log.Println("failed to create keyring:", err)
	}
	// TODO(leo): add cryptoKey search and print like keyRing
	if err := kms.createCryptoKeys(); err != nil {
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

// Sign will sign a plaintext message using a saved asymmetric private key.
// example keyName: "projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID/cryptoKeyVersions/1"
func (kms cloudKMS) Sign(message []byte) ([]byte, error) {
	var err error
	kmsService, err := cloudkms.New(kms.authedClient)
	if err != nil {
		return nil, err
	}
	// Find the digest of the message.
	digest := sha256.New()
	digest.Write(message)
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		kms.ProjectID, kms.LocationID, kms.KeyRingID, kms.CryptoKeyID)
	// Build the signing request.
	req := &cloudkms.AsymmetricSignRequest{
		Digest: &cloudkms.Digest{
			Sha256: string(digest.Sum(nil)),
		},
	}
	// Call the API.
	res, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.AsymmetricSign(parentName, req).Do()
	if err != nil {
		return nil, fmt.Errorf("asymmetric sign request failed: %+v", err)
	}
	return base64.StdEncoding.DecodeString(res.Signature)
}

// verifySignatureEC will verify that an 'EC_SIGN_P256_SHA256' signature is valid for a given message.
// example keyName: "projects/PROJECT_ID/locations/global/keyRings/RING_ID/cryptoKeys/KEY_ID/cryptoKeyVersions/1"
func (kms cloudKMS) Verify(signature, message []byte) error {
	var err error
	kmsService, err := cloudkms.New(kms.authedClient)
	if err != nil {
		return err
	}
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		kms.ProjectID, kms.LocationID, kms.KeyRingID, kms.CryptoKeyID)
	// Retrieve the public key from KMS.
	res, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.GetPublicKey(parentName).Do()
	if err != nil {
		return fmt.Errorf("failed to fetch public key: %+v", err)
	}
	// Parse the key.
	block, _ := pem.Decode([]byte(res.Pem))
	abstractKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %+v", err)
	}
	ecKey, ok := abstractKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("key '%s' is not EC", abstractKey)
	}
	// Verify Elliptic Curve signature.
	var parsedSig struct{ R, S *big.Int }
	_, err = asn1.Unmarshal(signature, &parsedSig)
	if err != nil {
		return fmt.Errorf("failed to parse signature bytes: %+v", err)
	}
	hash := sha256.New()
	hash.Write(message)
	digest := hash.Sum(nil)
	if !ecdsa.Verify(ecKey, digest, parsedSig.R, parsedSig.S) {
		return errors.New("signature verification failed")
	}
	return nil
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
	log.Printf("Created key ring %v\n", parent)
	return nil
}

func (kms cloudKMS) createCryptoKeys() error {
	client, err := cloudkms.New(kms.authedClient)
	if err != nil {
		return err
	}
	location := kms.LocationID
	// setup Key ring
	parent := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", kms.ProjectID, location, kms.KeyRingID)
	// create ENCRYPT_DECRYPT
	_, err = client.Projects.Locations.KeyRings.CryptoKeys.Create(
		parent, &cloudkms.CryptoKey{
			Purpose: "ENCRYPT_DECRYPT",
		}).CryptoKeyId(kms.CryptoKeyID).Do()
	if err != nil {
		log.Println(err)
	}
	log.Printf("Created crypto key %v\n", parent)
	// create ASYMMETRIC_SIGN
	_, err = client.Projects.Locations.KeyRings.CryptoKeys.Create(
		parent, &cloudkms.CryptoKey{
			Purpose: "ASYMMETRIC_SIGN",
			VersionTemplate: &cloudkms.CryptoKeyVersionTemplate{
				Algorithm: "EC_SIGN_P256_SHA256",
			},
		}).CryptoKeyId(kms.SigningKeyID).Do()
	if err != nil {
		log.Println(err)
	}
	log.Printf("Created crypto key %v\n", parent)

	return nil
}

package main

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: func() *schema.Provider {
			return &schema.Provider{
				Schema: map[string]*schema.Schema{
					"encryption_key": {
						Type:     schema.TypeString,
						Optional: true,
					},
				},
				ResourcesMap: map[string]*schema.Resource{
					"sops_age_key": resourceSopsAgeKey(),
				},
			}
		},
	})
}

func resourceSopsAgeKey() *schema.Resource {
	return &schema.Resource{
		Create: resourceSopsAgeKeyCreate,
		Read:   resourceSopsAgeKeyRead,
		Delete: resourceSopsAgeKeyDelete,

		Schema: map[string]*schema.Schema{
			"private_key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"public_key": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceSopsAgeKeyCreate(d *schema.ResourceData, m interface{}) error {
	// Generate age key pair
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}

	// Get the encryption key from the provider configuration
	encryptionKey, ok := d.GetOk("encryption_key")

	var encryptedPrivateKey string
	if ok {
		// Encrypt the private key
		encryptedPrivateKey, err = encryptWithAge(identity.String(), encryptionKey.(string))
		if err != nil {
			return err
		}
	} else {
		// Use the private key as is
		encryptedPrivateKey = identity.String()
	}

	// Set the keys in the Terraform state
	d.Set("private_key", encryptedPrivateKey)
	d.Set("public_key", identity.Recipient().String())
	d.SetId(fmt.Sprintf("sops-age-key-%s", identity.Recipient().String()))

	return resourceSopsAgeKeyRead(d, m)
}

func resourceSopsAgeKeyRead(d *schema.ResourceData, m interface{}) error {
	// No-op: All data is already in the state
	return nil
}

func resourceSopsAgeKeyDelete(d *schema.ResourceData, m interface{}) error {
	// No-op: Nothing to delete
	d.SetId("")
	return nil
}

func encryptWithAge(data, encryptionKey string) (string, error) {
	recipient, err := age.ParseX25519Recipient(encryptionKey)
	if err != nil {
		return "", err
	}

	var b bytes.Buffer
	armorWriter := armor.NewWriter(&b)
	writer, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		return "", err
	}

	_, err = io.WriteString(writer, data)
	if err != nil {
		return "", err
	}

	err = writer.Close()
	if err != nil {
		return "", err
	}

	err = armorWriter.Close()
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

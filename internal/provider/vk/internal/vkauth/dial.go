package vkauth

import (
	"gitlab.com/freeturn/free-turn-proxy/internal/provider/vk/internal/browserprofile"
	"gitlab.com/freeturn/free-turn-proxy/internal/provider/vk/internal/personanet"

	tlsclient "github.com/bogdanfinn/tls-client"
)

func (c *Client) newTLSClient(profile browserprofile.Profile, jar tlsclient.CookieJar) (tlsclient.HttpClient, error) {
	return personanet.NewClient(profile, c.dialer, jar)
}

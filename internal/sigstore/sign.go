// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sigstore

import (
	"os"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"google.golang.org/protobuf/encoding/protojson"
)

type SignKeyless struct {
	IdToken         string
	Intoto          bool
	Tsa             bool
	Rekor           bool
	SignConfigPath  string
	TrustedRootPath string
}

func NewSignKeyless() *SignKeyless {
	return &SignKeyless{
		Intoto: false,
		Tsa:    false,
		Rekor:  false,
	}
}

func (s *SignKeyless) Sign(dataPath string) (string, error) {
	var content sign.Content

	data, err := os.ReadFile(dataPath)
	if err != nil {
		return "", err
	}

	if s.Intoto {
		content = &sign.DSSEData{
			Data:        data,
			PayloadType: "application/vnd.in-toto+json",
		}
	} else {
		content = &sign.PlainData{
			Data: data,
		}
	}

	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return "", err
	}

	opts := sign.BundleOptions{}
	var signingConfig *root.SigningConfig

	if s.TrustedRootPath != "" {
		opts.TrustedRoot, err = root.NewTrustedRootFromPath(s.TrustedRootPath)
		if err != nil {
			return "", err
		}
	} else if s.SignConfigPath == "" {
		fetcher := fetcher.DefaultFetcher{}
		fetcher.SetHTTPUserAgent(util.ConstructUserAgent())

		tufOptions := &tuf.Options{
			Root:              tuf.StagingRoot(),
			RepositoryBaseURL: tuf.StagingMirror,
			Fetcher:           &fetcher,
		}
		tufClient, err := tuf.New(tufOptions)
		if err != nil {
			return "", err
		}
		opts.TrustedRoot, err = root.GetTrustedRoot(tufClient)
		if err != nil {
			return "", err
		}
	}

	if s.SignConfigPath != "" {
		signingConfig, err = root.NewSigningConfigFromPath(s.SignConfigPath)
		if err != nil {
			return "", err
		}
	} else {
		signingConfig, err = s.getDefaultSigningConfig()
		if err != nil {
			return "", err
		}
	}

	if s.IdToken != "" {
		fulcioURL, err := root.SelectService(signingConfig.FulcioCertificateAuthorityURLs(), []uint32{1}, time.Now())
		if err != nil {
			return "", err
		}
		fulcioOpts := &sign.FulcioOptions{
			BaseURL: fulcioURL,
			Timeout: time.Duration(30 * time.Second),
			Retries: 1,
		}
		opts.CertificateProvider = sign.NewFulcio(fulcioOpts)
		opts.CertificateProviderOptions = &sign.CertificateProviderOptions{
			IDToken: s.IdToken,
		}
	}

	if s.Tsa {
		tsaURLs, err := root.SelectServices(signingConfig.TimestampAuthorityURLs(),
			signingConfig.TimestampAuthorityURLsConfig(), []uint32{1}, time.Now())
		if err != nil {
			return "", err
		}
		for _, tsaURL := range tsaURLs {
			tsaOpts := &sign.TimestampAuthorityOptions{
				URL:     tsaURL,
				Timeout: time.Duration(30 * time.Second),
				Retries: 1,
			}
			opts.TimestampAuthorities = append(opts.TimestampAuthorities, sign.NewTimestampAuthority(tsaOpts))
		}
	}

	if s.Rekor {
		rekorURLs, err := root.SelectServices(signingConfig.RekorLogURLs(),
			signingConfig.RekorLogURLsConfig(), []uint32{1}, time.Now())
		if err != nil {
			return "", err
		}
		for _, rekorURL := range rekorURLs {
			rekorOpts := &sign.RekorOptions{
				BaseURL: rekorURL,
				Timeout: time.Duration(90 * time.Second),
				Retries: 1,
			}
			opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(rekorOpts))
		}
	}

	bundle, err := sign.Bundle(content, keypair, opts)
	if err != nil {
		return "", err
	}

	bundleJSON, err := protojson.Marshal(bundle)
	if err != nil {
		return "", err
	}

	return string(bundleJSON), nil
}

func (s *SignKeyless) getDefaultSigningConfig() (*root.SigningConfig, error) {
	now := time.Now()
	return root.NewSigningConfig(
		root.SigningConfigMediaType02,
		[]root.Service{
			{
				URL:                 "https://fulcio.sigstage.dev",
				MajorAPIVersion:     1,
				ValidityPeriodStart: now.Add(-time.Hour),
				ValidityPeriodEnd:   now.Add(time.Hour),
			},
		},
		[]root.Service{
			{
				URL:                 "https://oauth2.sigstage.dev/auth",
				MajorAPIVersion:     1,
				ValidityPeriodStart: now.Add(-time.Hour),
				ValidityPeriodEnd:   now.Add(time.Hour),
			},
		},
		[]root.Service{
			{
				URL:                 "https://rekor.sigstage.dev",
				MajorAPIVersion:     1,
				ValidityPeriodStart: now.Add(-time.Hour),
				ValidityPeriodEnd:   now.Add(time.Hour),
			},
		},
		root.ServiceConfiguration{
			Selector: 0,
		},
		[]root.Service{
			{
				URL:                 "https://timestamp.sigstage.dev/api/v1/timestamp",
				MajorAPIVersion:     1,
				ValidityPeriodStart: now.Add(-time.Hour),
				ValidityPeriodEnd:   now.Add(time.Hour),
			},
		},
		root.ServiceConfiguration{
			Selector: 0,
		},
	)
}

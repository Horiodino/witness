// Copyright 2022 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package options

import "github.com/spf13/cobra"

type SignOptions struct {
	SignerOptions            SignerOptions
	KMSSignerProviderOptions KMSSignerProviderOptions
	DataType                 string
	OutFilePath              string
	InFilePath               string
	TimestampServers         []string
	// Keyless signing options
	Keyless         bool
	IdToken         string
	Intoto          bool
	UseTsa          bool
	UseRekor        bool
	SignConfigPath  string
	TrustedRootPath string
}

var RequiredSignFlags = []string{
	"infile",
	"outfile",
}

func (so *SignOptions) AddFlags(cmd *cobra.Command) {
	so.SignerOptions.AddFlags(cmd)
	so.KMSSignerProviderOptions.AddFlags(cmd)
	cmd.Flags().StringVarP(&so.DataType, "datatype", "t", "https://witness.testifysec.com/policy/v0.1", "The URI reference to the type of data being signed. Defaults to the Witness policy type")
	cmd.Flags().StringVarP(&so.OutFilePath, "outfile", "o", "", "File to write signed data. Defaults to stdout")
	cmd.Flags().StringVarP(&so.InFilePath, "infile", "f", "", "Witness policy file to sign")
	cmd.Flags().StringSliceVar(&so.TimestampServers, "timestamp-servers", []string{}, "Timestamp Authority Servers to use when signing envelope")

	cmd.Flags().BoolVar(&so.Keyless, "keyless", false, "Use keyless signing with Sigstore")
	cmd.Flags().StringVar(&so.IdToken, "id-token", "", "OIDC identity token for keyless signing")
	cmd.Flags().BoolVar(&so.Intoto, "intoto", false, "Sign as in-toto attestation")
	cmd.Flags().BoolVar(&so.UseTsa, "tsa", false, "Use timestamp authority during keyless signing")
	cmd.Flags().BoolVar(&so.UseRekor, "rekor", true, "Use Rekor transparency log during keyless signing (defaults to true)")
	cmd.Flags().StringVar(&so.SignConfigPath, "sign-config", "", "Path to the signing configuration file")
	cmd.Flags().StringVar(&so.TrustedRootPath, "trusted-root", "", "Path to the trusted root file")

	cmd.MarkFlagsRequiredTogether(RequiredSignFlags...)
}

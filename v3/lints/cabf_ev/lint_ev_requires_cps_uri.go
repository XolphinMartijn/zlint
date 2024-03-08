/*
 * ZLint Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package cabf_ev

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"strings"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "ev_requires_cps_uri",
			Description:   "EV TLS certificates MUST include an HTTP accessible CPS URI Policy Qualifier",
			Citation:      "EVG 9.7 (3)",
			Source:        lint.CABFEVGuidelines,
			EffectiveDate: util.EVG1_2Date,
		},
		Lint: NewEvRequiresCpsUri,
	})
}

type EvRequiresCpsUri struct{}

func NewEvRequiresCpsUri() lint.LintInterface {
	return &EvRequiresCpsUri{}
}

func (l *EvRequiresCpsUri) CheckApplies(c *x509.Certificate) bool {
	return util.IsEV(c.PolicyIdentifiers) && util.IsSubscriberCert(c)
}

func (l *EvRequiresCpsUri) Execute(c *x509.Certificate) *lint.LintResult {

	hasCpsOid := false
	hasHttpCpsUri := false

	for _, qualifiers := range c.QualifierId {
		for _, qt := range qualifiers {
			if qt.Equal(util.CpsOID) {
				hasCpsOid = true
			}
		}
	}

	for _, uri := range c.CPSuri {
		for _, cps := range uri {
			if strings.HasPrefix(cps, "http://") || strings.HasPrefix(cps, "https://") {
				hasHttpCpsUri = true
			}
		}
	}

	if hasCpsOid && hasHttpCpsUri {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error}
	}

}

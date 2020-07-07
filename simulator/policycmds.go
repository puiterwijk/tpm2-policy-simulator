// Copyright 2020 Patrick Uiterwijk
//
// Licensed under the EUPL-1.2-or-later
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package simulator

import (
	"fmt"

	"github.com/puiterwijk/tpm2-policy-simulator/simulator/constants"
)

func (s *Tpm2PolicySimulator) PolicySigned(authObject_name TPM2B_NAME, policyRef []byte) error {
	return s.policyUpdate(constants.TPM_CC_PolicySigned, authObject_name.getBytes(), policyRef)
}

func (s *Tpm2PolicySimulator) PolicySecret(authEntity_name TPM2B_NAME, policyRef []byte) error {
	return s.policyUpdate(constants.TPM_CC_PolicySecret, authEntity_name.getBytes(), policyRef)
}

func (s *Tpm2PolicySimulator) PolicyTicket(authObject_name TPM2B_NAME, policyRef []byte) error {
	return s.policyUpdate(constants.TPM_CC_PolicyTicket, authObject_name.getBytes(), policyRef)
}

func (s *Tpm2PolicySimulator) PolicyOr(pHashList [][]byte) error {
	// a
	digests := []byte{}
	for _, dig := range pHashList {
		digests = append(digests, dig...)
	}
	// b
	s.reset()
	// c
	return s.extend(constants.TPM_CC_PolicyOR.GetBytes(), digests)
}

func (s *Tpm2PolicySimulator) PolicyPCR(sel *PcrSelection) error {
	pcrs, err := sel.getSelection()
	if err != nil {
		return fmt.Errorf("Error getting PCRs: %s", err)
	}
	pcrDigest, err := sel.getDigest()
	if err != nil {
		return fmt.Errorf("Error getting PCR digest: %s", err)
	}
	pcrDigester := s.hashfunc.New()
	_, err = pcrDigester.Write(pcrDigest)
	if err != nil {
		return fmt.Errorf("Error writing to pcrDigester: %s", err)
	}
	pcrDigest = pcrDigester.Sum(nil)

	return s.extend(constants.TPM_CC_PolicyPCR.GetBytes(), pcrs, pcrDigest)
}

func (s *Tpm2PolicySimulator) PolicyLocality(locality byte) error {
	return s.extend(
		constants.TPM_CC_PolicyLocality.GetBytes(),
		[]byte{locality},
	)
}

/* TODO: PolicyNV */

/* TODO: PolicyCounterTimer */

func (s *Tpm2PolicySimulator) PolicyCommandCode(cc constants.TPM_CC) error {
	return s.extend(
		constants.TPM_CC_PolicyCommandCode.GetBytes(),
		cc.GetBytes(),
	)
}

func (s *Tpm2PolicySimulator) PolicyPhysicalPresence() error {
	return s.extend(
		constants.TPM_CC_PolicyPhysicalPresence.GetBytes(),
	)
}

func (s *Tpm2PolicySimulator) PolicyCpHash(cpHashA []byte) error {
	return s.extend(
		constants.TPM_CC_PolicyCpHash.GetBytes(),
		cpHashA,
	)
}

func (s *Tpm2PolicySimulator) PolicyNameHash(nameHash []byte) error {
	return s.extend(
		constants.TPM_CC_PolicyNameHash.GetBytes(),
		nameHash,
	)
}

/* TODO: PolicyDuplicationSelect (not implemented) */

func (s *Tpm2PolicySimulator) PolicyAuthorize(keySign TPM2B_NAME, policyRef []byte) error {
	s.reset()
	return s.policyUpdate(constants.TPM_CC_PolicyAuthorize, keySign.getBytes(), policyRef)
}

func (s *Tpm2PolicySimulator) PolicyAuthValue() error {
	return s.extend(
		constants.TPM_CC_PolicyAuthValue.GetBytes(),
	)
}

func (s *Tpm2PolicySimulator) PolicyPassword() error {
	return s.extend(
		constants.TPM_CC_PolicyAuthValue.GetBytes(),
	)
}

func (s *Tpm2PolicySimulator) PolicyNvWritten(writtenSet bool) error {
	var writtenSetByte byte
	if writtenSet {
		writtenSetByte = 0x1
	} else {
		writtenSetByte = 0x0
	}
	return s.extend(
		constants.TPM_CC_PolicyNvWritten.GetBytes(),
		[]byte{writtenSetByte},
	)
}

/* TODO: PolicyTemplate (not implemented) */

/* TODO: PolicyAuthorizeNV */

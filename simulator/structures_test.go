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
	"bytes"
	_ "crypto/sha256"

	"crypto"
	"testing"

	"github.com/puiterwijk/tpm2-policy-simulator/simulator/constants"
)

func ensurePolicyDigest(t *testing.T, sim *Tpm2PolicySimulator, expected []byte) {
	if !bytes.Equal(sim.policyDigest, expected) {
		t.Errorf("Policy digest not as expected: %#v != %#v", sim.policyDigest, expected)
	}
}

func TestNewSimulator(t *testing.T) {
	sim, err := NewSimulator(crypto.SHA256)
	if err != nil {
		t.Errorf("NewSimulator failed: %s", err)
	}
	ensurePolicyDigest(t, sim, make([]byte, crypto.SHA256.Size()))
}

func TestGetDigest(t *testing.T) {
	sim, err := NewSimulator(crypto.SHA256)
	if err != nil {
		t.Errorf("NewSimulator failed: %s", err)
	}
	sim.extend([]byte{0x1, 0x2, 0x3})
	ensurePolicyDigest(t, sim, sim.GetDigest())
}

func TestReset(t *testing.T) {
	sim, err := NewSimulator(crypto.SHA256)
	if err != nil {
		t.Errorf("NewSimulator failed: %s", err)
	}
	sim.extend([]byte{0x1, 0x2, 0x3})
	sim.reset()
	ensurePolicyDigest(t, sim, make([]byte, crypto.SHA256.Size()))
}

func TestExtend(t *testing.T) {
	sim, err := NewSimulator(crypto.SHA256)
	if err != nil {
		t.Errorf("NewSimulator failed: %s", err)
	}
	sim.extend([]byte{0x1, 0x2, 0x3})
	ensurePolicyDigest(t, sim, []byte{0x44, 0x0, 0xc1, 0xb8, 0x63, 0x8a, 0xc2, 0xdc, 0xe3, 0xce, 0xe, 0x10, 0xb8, 0xa8, 0x91, 0x17, 0x59, 0x26, 0xca, 0x29, 0xa7, 0x24, 0x6e, 0x96, 0xef, 0x41, 0xaa, 0x81, 0xf1, 0x12, 0x1, 0xcc})
}

func TestPolicyUpdate(t *testing.T) {
	sim, err := NewSimulator(crypto.SHA256)
	if err != nil {
		t.Errorf("NewSimulator failed: %s", err)
	}
	sim.policyUpdate(constants.TPM_CC_Unseal, []byte{0x1, 0x2}, []byte{0x3, 0x4})
	ensurePolicyDigest(t, sim, []byte{0x70, 0x42, 0xb6, 0x8a, 0x3, 0x56, 0xba, 0xed, 0xbc, 0x12, 0x56, 0x93, 0x18, 0x33, 0xe3, 0x5d, 0x5a, 0xe, 0x53, 0x76, 0x20, 0xc4, 0x1a, 0x5a, 0xf3, 0x3b, 0x22, 0x93, 0xd2, 0x29, 0xbd, 0xd5})
}

func TestNameGetBytes(t *testing.T) {
	name := TPM2B_NAME([]byte{0x1, 0x2})
	if !bytes.Equal(name.getBytes(), []byte{0x1, 0x2}) {
		t.Errorf("Name.GetBytes doesn't work")
	}
}

func TestAlgHdr(t *testing.T) {
	alg := tpm_alg_hash_from_crypto_hash(crypto.SHA256)
	if alg != 0xB {
		t.Errorf("SHA256 digest not returned correctly")
	}
	if !bytes.Equal(alg.algHdr(), []byte{0x00, 0xb}) {
		t.Errorf("Alghdr is incorrect: %#v", alg.algHdr())
	}
}

func TestPcrSelection(t *testing.T) {
	sel := NewPcrSelection()
	sel.AddSelection(crypto.SHA256, 2, []byte{0x3, 0x4})
	sel.AddSelection(crypto.SHA256, 1, []byte{0x1, 0x2})
	sel.AddSelection(crypto.SHA256, 19, []byte{0x5, 0x6})

	digest, err := sel.getDigest()
	if err != nil {
		t.Errorf("Error getting digest: %s", err)
	}
	if !bytes.Equal(digest, []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6}) {
		t.Errorf("Digest is invalid: %#v", digest)
	}

	selection, err := sel.getSelection()
	if err != nil {
		t.Errorf("Error getting selection: %s", err)
	}
	if !bytes.Equal(selection, []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0xb, 0x3, 0x6, 0x0, 0x8}) {
		t.Errorf("Selection is invalid: %#v", selection)
	}
}

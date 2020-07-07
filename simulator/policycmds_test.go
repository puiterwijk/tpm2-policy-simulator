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
	_ "crypto/sha256"

	"crypto"
	"testing"

	"github.com/puiterwijk/tpm2-policy-simulator/simulator/constants"
)

func TestPolicyOr(t *testing.T) {
	sim, _ := NewSimulator(crypto.SHA256)
	diglist := [][]byte{
		[]byte{0x1, 0x2},
		[]byte{0x3, 0x4},
	}
	sim.PolicyOr(diglist)
	ensurePolicyDigest(t, sim, []byte{252, 200, 17, 232, 137, 217, 130, 51, 54, 22, 184, 131, 2, 134, 99, 130, 175, 216, 159, 174, 203, 165, 35, 19, 187, 56, 167, 208, 3, 128, 11, 12})
}

func TestPolicyPCR(t *testing.T) {
	sim, _ := NewSimulator(crypto.SHA256)
	pcrsel := NewPcrSelection()
	pcrsel.AddSelection(crypto.SHA256, 1, []byte{0x2})
	pcrsel.AddSelection(crypto.SHA256, 0, []byte{0x1})
	sim.PolicyPCR(pcrsel)
	ensurePolicyDigest(t, sim, []byte{254, 184, 78, 133, 193, 118, 186, 241, 50, 93, 87, 223, 230, 90, 244, 116, 20, 176, 157, 194, 202, 167, 243, 168, 251, 148, 115, 22, 214, 186, 42, 206})
}

func TestPolicyAuthorize(t *testing.T) {
	sim, _ := NewSimulator(crypto.SHA256)
	name := []byte{0, 11, 193, 250, 90, 232, 195, 252, 72, 138, 2, 239, 201, 248, 19, 201, 61, 243, 44, 66, 74, 28, 55, 75, 247, 220, 179, 195, 161, 75, 130, 15, 103, 27}
	sim.PolicyAuthorize(name, []byte("test"))
	ensurePolicyDigest(t, sim, []byte{21, 93, 66, 136, 50, 150, 6, 102, 147, 141, 90, 72, 71, 66, 191, 105, 242, 157, 239, 78, 184, 186, 42, 80, 55, 246, 211, 33, 41, 14, 218, 159})
}

func TestPolicyCommandCode(t *testing.T) {
	sim, _ := NewSimulator(crypto.SHA256)
	sim.PolicyCommandCode(constants.TPM_CC_Unseal)
	ensurePolicyDigest(t, sim, []byte{230, 19, 19, 112, 118, 82, 75, 222, 72, 117, 51, 134, 88, 132, 233, 115, 46, 190, 227, 170, 203, 9, 93, 148, 166, 222, 73, 46, 192, 108, 70, 250})
}

func TestPolicyPhysicalPresence(t *testing.T) {
	sim, _ := NewSimulator(crypto.SHA256)
	sim.PolicyPhysicalPresence()
	ensurePolicyDigest(t, sim, []byte{13, 124, 103, 71, 177, 185, 250, 203, 186, 3, 73, 32, 151, 170, 157, 90, 247, 146, 229, 239, 192, 115, 70, 224, 95, 157, 170, 139, 61, 158, 19, 181})
}

func TestPolicyCpHash(t *testing.T) {
	sim, _ := NewSimulator(crypto.SHA256)
	sim.PolicyCpHash([]byte{252, 200, 17, 232, 137, 217, 130, 51, 54, 22, 184, 131, 2, 134, 99, 130, 175, 216, 159, 174, 203, 165, 35, 19, 187, 56, 167, 208, 3, 128, 11, 12})
	ensurePolicyDigest(t, sim, []byte{75, 24, 197, 124, 242, 73, 145, 176, 232, 76, 61, 173, 110, 164, 78, 88, 29, 195, 36, 224, 222, 205, 228, 74, 182, 42, 231, 232, 16, 13, 119, 135})
}

func TestPolicyNameHash(t *testing.T) {
	sim, _ := NewSimulator(crypto.SHA256)
	sim.PolicyNameHash([]byte{252, 200, 17, 232, 137, 217, 130, 51, 54, 22, 184, 131, 2, 134, 99, 130, 175, 216, 159, 174, 203, 165, 35, 19, 187, 56, 167, 208, 3, 128, 11, 12})
	ensurePolicyDigest(t, sim, []byte{181, 153, 215, 162, 227, 189, 169, 206, 40, 150, 190, 226, 208, 202, 64, 188, 230, 180, 75, 133, 160, 224, 56, 107, 31, 47, 228, 43, 220, 253, 150, 33})
}

func TestPolicyAuthValue(t *testing.T) {
	sim, _ := NewSimulator(crypto.SHA256)
	sim.PolicyAuthValue()
	ensurePolicyDigest(t, sim, []byte{143, 205, 33, 105, 171, 146, 105, 78, 12, 99, 63, 26, 183, 114, 132, 43, 130, 65, 187, 194, 2, 136, 152, 31, 199, 172, 30, 221, 193, 253, 219, 14})
}

func TestPolicyPassword(t *testing.T) {
	sim, _ := NewSimulator(crypto.SHA256)
	sim.PolicyPassword()
	ensurePolicyDigest(t, sim, []byte{143, 205, 33, 105, 171, 146, 105, 78, 12, 99, 63, 26, 183, 114, 132, 43, 130, 65, 187, 194, 2, 136, 152, 31, 199, 172, 30, 221, 193, 253, 219, 14})
}

func TestPolicyNvWritten(t *testing.T) {
	sim, _ := NewSimulator(crypto.SHA256)
	sim.PolicyNvWritten(false)
	ensurePolicyDigest(t, sim, []byte{60, 50, 99, 35, 103, 14, 40, 173, 55, 189, 87, 246, 59, 76, 195, 77, 38, 171, 32, 94, 242, 47, 39, 92, 88, 212, 127, 171, 36, 133, 70, 110})
	sim.reset()
	sim.PolicyNvWritten(true)
	ensurePolicyDigest(t, sim, []byte{247, 136, 125, 21, 138, 232, 211, 139, 224, 172, 83, 25, 243, 122, 158, 7, 97, 139, 245, 72, 133, 69, 60, 122, 84, 221, 176, 198, 166, 25, 59, 235})
}

func TestMultiple(t *testing.T) {
	sim, _ := NewSimulator(crypto.SHA256)
	sim.PolicyLocality(3)
	diglist := [][]byte{
		[]byte{0x1, 0x2},
		[]byte{0x3, 0x4},
	}
	sim.PolicyOr(diglist)
	pcrsel := NewPcrSelection()
	pcrsel.AddSelection(crypto.SHA256, 1, []byte{0x2})
	pcrsel.AddSelection(crypto.SHA256, 0, []byte{0x1})
	sim.PolicyPCR(pcrsel)
	name := []byte{0, 11, 193, 250, 90, 232, 195, 252, 72, 138, 2, 239, 201, 248, 19, 201, 61, 243, 44, 66, 74, 28, 55, 75, 247, 220, 179, 195, 161, 75, 130, 15, 103, 27}
	testdig := []byte{252, 200, 17, 232, 137, 217, 130, 51, 54, 22, 184, 131, 2, 134, 99, 130, 175, 216, 159, 174, 203, 165, 35, 19, 187, 56, 167, 208, 3, 128, 11, 12}
	sim.PolicyAuthorize(name, []byte("test"))
	sim.PolicyCommandCode(constants.TPM_CC_PolicyAuthorize)
	sim.PolicyPhysicalPresence()
	sim.PolicyNameHash(testdig)
	sim.PolicyAuthValue()
	sim.PolicyPassword()
	sim.PolicyNvWritten(false)

	ensurePolicyDigest(t, sim, []byte{105, 99, 114, 33, 0, 95, 91, 19, 187, 202, 115, 58, 115, 76, 162, 216, 29, 196, 37, 97, 93, 11, 104, 3, 196, 45, 50, 150, 114, 82, 99, 129})
}

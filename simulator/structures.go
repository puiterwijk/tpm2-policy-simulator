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
	"crypto"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/puiterwijk/tpm2-policy-simulator/simulator/constants"
)

// Tpm2PolicySimulator is a structure that helps simulate policies
type Tpm2PolicySimulator struct {
	hashfunc     crypto.Hash
	policyDigest []byte
}

func NewSimulator(hashfunc crypto.Hash) (*Tpm2PolicySimulator, error) {
	sim := &Tpm2PolicySimulator{
		hashfunc: hashfunc,
	}
	sim.reset()
	return sim, nil
}

func (s *Tpm2PolicySimulator) GetDigest() []byte {
	return s.policyDigest
}

func (s *Tpm2PolicySimulator) reset() {
	s.policyDigest = make([]byte, s.hashfunc.Size())
}

func (s *Tpm2PolicySimulator) extend(new ...[]byte) error {
	hasher := s.hashfunc.New()
	var err error
	_, err = hasher.Write(s.policyDigest)
	if err != nil {
		return fmt.Errorf("Error extending policy: %s", err)
	}
	for _, new := range new {
		_, err = hasher.Write(new)
		if err != nil {
			return fmt.Errorf("Error extending policy: %s", err)
		}
	}
	s.policyDigest = hasher.Sum(nil)
	return nil
}

func (s *Tpm2PolicySimulator) policyUpdate(cc constants.TPM_CC, arg2, arg3 []byte) error {
	var err error
	err = s.extend(cc.GetBytes(), arg2)
	if err != nil {
		return fmt.Errorf("Error updating policy: %s", err)
	}
	err = s.extend(arg3)
	if err != nil {
		return fmt.Errorf("Error updating policy: %s", err)
	}
	return nil
}

type TPM2B_NAME []byte

func (t *TPM2B_NAME) getBytes() []byte {
	return []byte(*t)
}

type tpm_alg_hash int

const (
	tpm_alg_hash_sha256 tpm_alg_hash = 0x00B
)

func (t tpm_alg_hash) algHdr() []byte {
	alghdr := make([]byte, 2)
	binary.BigEndian.PutUint16(alghdr[0:2], uint16(t))
	return alghdr
}

func (t tpm_alg_hash) ToCryptoHash() crypto.Hash {
	switch t {
	case tpm_alg_hash_sha256:
		return crypto.SHA256
	default:
		panic("Unsupported hash type requested")
	}
}

func tpm_alg_hash_from_crypto_hash(h crypto.Hash) tpm_alg_hash {
	switch h {
	case crypto.SHA256:
		return tpm_alg_hash_sha256
	default:
		panic("Unsupported hash type requested")
	}
}

type PcrSelection struct {
	selections map[tpm_alg_hash]map[int][]byte
}

func NewPcrSelection() *PcrSelection {
	return &PcrSelection{
		selections: make(map[tpm_alg_hash]map[int][]byte),
	}
}

func (p *PcrSelection) GetHashAlgos() []tpm_alg_hash {
	algs := make([]int, len(p.selections))
	i := 0
	for algid := range p.selections {
		algs[i] = int(algid)
		i++
	}
	sort.Ints(algs)
	algsR := make([]tpm_alg_hash, len(algs))
	for i, alg := range algs {
		algsR[i] = tpm_alg_hash(alg)
	}
	return algsR
}

func (p *PcrSelection) GetValues(hashalg tpm_alg_hash) map[int][]byte {
	return p.selections[hashalg]
}

func (p *PcrSelection) GetPcrIDs(hashalg tpm_alg_hash) []int {
	sel := p.selections[hashalg]
	pcrids := make([]int, len(sel))
	i := 0
	for pcrid := range sel {
		pcrids[i] = pcrid
		i++
	}
	sort.Ints(pcrids)
	return pcrids
}

func (p *PcrSelection) AddSelection(hash crypto.Hash, pcrid int, val []byte) error {
	algid := tpm_alg_hash_from_crypto_hash(hash)
	_, ok := p.selections[algid]
	if !ok {
		p.selections[algid] = make(map[int][]byte)
	}
	_, has := p.selections[algid][pcrid]
	if has {
		return fmt.Errorf("Other value for pcr id %d already provided", pcrid)
	}
	p.selections[algid][pcrid] = val
	return nil
}

func (p *PcrSelection) loopInOrder(f func(alg_id tpm_alg_hash, pcrid int, val []byte) error) error {
	algs := p.GetHashAlgos()

	for _, algid := range algs {
		pcrids := p.GetPcrIDs(algid)

		for _, pcrid := range pcrids {
			if err := f(tpm_alg_hash(algid), pcrid, p.selections[tpm_alg_hash(algid)][pcrid]); err != nil {
				return fmt.Errorf("Error in looped function: %s", err)
			}
		}
	}
	return nil
}

func (p *PcrSelection) getSelection() ([]byte, error) {
	buf := new(bytes.Buffer)

	// First build the TPML_PCR_SELECTION "count" field
	count := make([]byte, 4)
	binary.BigEndian.PutUint32(count, uint32(len(p.selections)))
	_, err := buf.Write(count)
	if err != nil {
		return nil, err
	}

	var pcrSelect [3]byte
	writePcrSelect := func() error {
		_, err := buf.Write(pcrSelect[:])
		if err != nil {
			return err
		}
		pcrSelect[0] = 0x00
		pcrSelect[1] = 0x00
		pcrSelect[2] = 0x00
		return nil
	}

	var lastalg tpm_alg_hash = -1
	err = p.loopInOrder(func(alg_id tpm_alg_hash, pcrid int, val []byte) error {
		if lastalg != alg_id {
			if lastalg != -1 {
				writePcrSelect()
			}
			_, err := buf.Write(alg_id.algHdr())
			if err != nil {
				return err
			}
			err = buf.WriteByte(3)
			if err != nil {
				return err
			}
			lastalg = alg_id
		}

		// Set the specific bit in the pcrSelect
		selSlot := pcrid / 8
		selPos := pcrid % 8
		pcrSelect[selSlot] |= (1 << selPos)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error building pcrs: %s", err)
	}
	// Finish the last write
	err = writePcrSelect()
	return buf.Bytes(), err
}

func (p *PcrSelection) GetDigest() ([]byte, error) {
	buf := new(bytes.Buffer)

	err := p.loopInOrder(func(alg_id tpm_alg_hash, pcrid int, val []byte) error {
		_, err := buf.Write(val)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error getting digest: %s", err)
	}

	return buf.Bytes(), nil
}

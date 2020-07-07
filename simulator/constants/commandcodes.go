package constants

import (
	"encoding/binary"
)

type TPM_CC uint32

func (c TPM_CC) GetBytes() []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b[0:], uint32(c))
	return b
}

const (
	TPM_CC_NV_UndefineSpaceSpecial    TPM_CC = 0x0000011f
	TPM_CC_FIRST                      TPM_CC = TPM_CC_NV_UndefineSpaceSpecial
	TPM_CC_EvictControl               TPM_CC = 0x00000120
	TPM_CC_HierarchyControl           TPM_CC = 0x00000121
	TPM_CC_NV_UndefineSpace           TPM_CC = 0x00000122
	TPM_CC_ChangeEPS                  TPM_CC = 0x00000124
	TPM_CC_ChangePPS                  TPM_CC = 0x00000125
	TPM_CC_Clear                      TPM_CC = 0x00000126
	TPM_CC_ClearControl               TPM_CC = 0x00000127
	TPM_CC_ClockSet                   TPM_CC = 0x00000128
	TPM_CC_HierarchyChangeAuth        TPM_CC = 0x00000129
	TPM_CC_NV_DefineSpace             TPM_CC = 0x0000012a
	TPM_CC_PCR_Allocate               TPM_CC = 0x0000012b
	TPM_CC_PCR_SetAuthPolicy          TPM_CC = 0x0000012c
	TPM_CC_PP_Commands                TPM_CC = 0x0000012d
	TPM_CC_SetPrimaryPolicy           TPM_CC = 0x0000012e
	TPM_CC_FieldUpgradeStart          TPM_CC = 0x0000012f
	TPM_CC_ClockRateAdjust            TPM_CC = 0x00000130
	TPM_CC_CreatePrimary              TPM_CC = 0x00000131
	TPM_CC_NV_GlobalWriteLock         TPM_CC = 0x00000132
	TPM_CC_GetCommandAuditDigest      TPM_CC = 0x00000133
	TPM_CC_NV_Increment               TPM_CC = 0x00000134
	TPM_CC_NV_SetBits                 TPM_CC = 0x00000135
	TPM_CC_NV_Extend                  TPM_CC = 0x00000136
	TPM_CC_NV_Write                   TPM_CC = 0x00000137
	TPM_CC_NV_WriteLock               TPM_CC = 0x00000138
	TPM_CC_DictionaryAttackLockReset  TPM_CC = 0x00000139
	TPM_CC_DictionaryAttackParameters TPM_CC = 0x0000013a
	TPM_CC_NV_ChangeAuth              TPM_CC = 0x0000013b
	TPM_CC_PCR_Event                  TPM_CC = 0x0000013c
	TPM_CC_PCR_Reset                  TPM_CC = 0x0000013d
	TPM_CC_SequenceComplete           TPM_CC = 0x0000013e
	TPM_CC_SetAlgorithmSet            TPM_CC = 0x0000013f
	TPM_CC_SetCommandCodeAuditStatus  TPM_CC = 0x00000140
	TPM_CC_FieldUpgradeData           TPM_CC = 0x00000141
	TPM_CC_IncrementalSelfTest        TPM_CC = 0x00000142
	TPM_CC_SelfTest                   TPM_CC = 0x00000143
	TPM_CC_Startup                    TPM_CC = 0x00000144
	TPM_CC_Shutdown                   TPM_CC = 0x00000145
	TPM_CC_StirRandom                 TPM_CC = 0x00000146
	TPM_CC_ActivateCredential         TPM_CC = 0x00000147
	TPM_CC_Certify                    TPM_CC = 0x00000148
	TPM_CC_PolicyNV                   TPM_CC = 0x00000149
	TPM_CC_CertifyCreation            TPM_CC = 0x0000014a
	TPM_CC_Duplicate                  TPM_CC = 0x0000014b
	TPM_CC_GetTime                    TPM_CC = 0x0000014c
	TPM_CC_GetSessionAuditDigest      TPM_CC = 0x0000014d
	TPM_CC_NV_Read                    TPM_CC = 0x0000014e
	TPM_CC_NV_ReadLock                TPM_CC = 0x0000014f
	TPM_CC_ObjectChangeAuth           TPM_CC = 0x00000150
	TPM_CC_PolicySecret               TPM_CC = 0x00000151
	TPM_CC_Rewrap                     TPM_CC = 0x00000152
	TPM_CC_Create                     TPM_CC = 0x00000153
	TPM_CC_ECDH_ZGen                  TPM_CC = 0x00000154
	TPM_CC_HMAC                       TPM_CC = 0x00000155
	TPM_CC_Import                     TPM_CC = 0x00000156
	TPM_CC_Load                       TPM_CC = 0x00000157
	TPM_CC_Quote                      TPM_CC = 0x00000158
	TPM_CC_RSA_Decrypt                TPM_CC = 0x00000159
	TPM_CC_HMAC_Start                 TPM_CC = 0x0000015b
	TPM_CC_SequenceUpdate             TPM_CC = 0x0000015c
	TPM_CC_Sign                       TPM_CC = 0x0000015d
	TPM_CC_Unseal                     TPM_CC = 0x0000015e
	TPM_CC_PolicySigned               TPM_CC = 0x00000160
	TPM_CC_ContextLoad                TPM_CC = 0x00000161
	TPM_CC_ContextSave                TPM_CC = 0x00000162
	TPM_CC_ECDH_KeyGen                TPM_CC = 0x00000163
	TPM_CC_EncryptDecrypt             TPM_CC = 0x00000164
	TPM_CC_FlushContext               TPM_CC = 0x00000165
	TPM_CC_LoadExternal               TPM_CC = 0x00000167
	TPM_CC_MakeCredential             TPM_CC = 0x00000168
	TPM_CC_NV_ReadPublic              TPM_CC = 0x00000169
	TPM_CC_PolicyAuthorize            TPM_CC = 0x0000016a
	TPM_CC_PolicyAuthValue            TPM_CC = 0x0000016b
	TPM_CC_PolicyCommandCode          TPM_CC = 0x0000016c
	TPM_CC_PolicyCounterTimer         TPM_CC = 0x0000016d
	TPM_CC_PolicyCpHash               TPM_CC = 0x0000016e
	TPM_CC_PolicyLocality             TPM_CC = 0x0000016f
	TPM_CC_PolicyNameHash             TPM_CC = 0x00000170
	TPM_CC_PolicyOR                   TPM_CC = 0x00000171
	TPM_CC_PolicyTicket               TPM_CC = 0x00000172
	TPM_CC_ReadPublic                 TPM_CC = 0x00000173
	TPM_CC_RSA_Encrypt                TPM_CC = 0x00000174
	TPM_CC_StartAuthSession           TPM_CC = 0x00000176
	TPM_CC_VerifySignature            TPM_CC = 0x00000177
	TPM_CC_ECC_Parameters             TPM_CC = 0x00000178
	TPM_CC_FirmwareRead               TPM_CC = 0x00000179
	TPM_CC_GetCapability              TPM_CC = 0x0000017a
	TPM_CC_GetRandom                  TPM_CC = 0x0000017b
	TPM_CC_GetTestResult              TPM_CC = 0x0000017c
	TPM_CC_Hash                       TPM_CC = 0x0000017d
	TPM_CC_PCR_Read                   TPM_CC = 0x0000017e
	TPM_CC_PolicyPCR                  TPM_CC = 0x0000017f
	TPM_CC_PolicyRestart              TPM_CC = 0x00000180
	TPM_CC_ReadClock                  TPM_CC = 0x00000181
	TPM_CC_PCR_Extend                 TPM_CC = 0x00000182
	TPM_CC_PCR_SetAuthValue           TPM_CC = 0x00000183
	TPM_CC_NV_Certify                 TPM_CC = 0x00000184
	TPM_CC_EventSequenceComplete      TPM_CC = 0x00000185
	TPM_CC_HashSequenceStart          TPM_CC = 0x00000186
	TPM_CC_PolicyPhysicalPresence     TPM_CC = 0x00000187
	TPM_CC_PolicyDuplicationSelect    TPM_CC = 0x00000188
	TPM_CC_PolicyGetDigest            TPM_CC = 0x00000189
	TPM_CC_TestParms                  TPM_CC = 0x0000018a
	TPM_CC_Commit                     TPM_CC = 0x0000018b
	TPM_CC_PolicyPassword             TPM_CC = 0x0000018c
	TPM_CC_ZGen_2Phase                TPM_CC = 0x0000018d
	TPM_CC_EC_Ephemeral               TPM_CC = 0x0000018e
	TPM_CC_PolicyNvWritten            TPM_CC = 0x0000018f
	TPM_CC_PolicyTemplate             TPM_CC = 0x00000190
	TPM_CC_CreateLoaded               TPM_CC = 0x00000191
	TPM_CC_PolicyAuthorizeNV          TPM_CC = 0x00000192
	TPM_CC_EncryptDecrypt2            TPM_CC = 0x00000193
	TPM_CC_AC_GetCapability           TPM_CC = 0x00000194
	TPM_CC_AC_Send                    TPM_CC = 0x00000195
	TPM_CC_Policy_AC_SendSelect       TPM_CC = 0x00000196
	TPM_CC_CertifyX509                TPM_CC = 0x00000197
	TPM_CC_ACT_SetTimeout             TPM_CC = 0x00000198
	TPM_CC_LAST                       TPM_CC = TPM_CC_ACT_SetTimeout

	CC_VEND                TPM_CC = 0x20000000
	TPM_CC_Vendor_TCG_Test TPM_CC = CC_VEND + 0x0000
)

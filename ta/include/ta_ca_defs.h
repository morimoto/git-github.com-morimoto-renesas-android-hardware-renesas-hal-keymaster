#ifndef ANDROID_OPTEE_TA_CA_DEFS_H
#define ANDROID_OPTEE_TA_CA_DEFS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#define STR_TRACE_USER_TA "KEYSTORE"

/**
 * Authorization tags each have an associated type.  This enumeration facilitates tagging each with
 * a type, by using the high four bits (of an implied 32-bit unsigned enum value) to specify up to
 * 16 data types.  These values are ORed with tag IDs to generate the final tag ID values.
 */
typedef enum {
	KM_INVALID = 0 << 28, /* Invalid type, used to designate a tag as uninitialized */
	KM_ENUM = 1 << 28,
	KM_ENUM_REP = 2 << 28, /* Repeatable enumeration value. */
	KM_UINT = 3 << 28,
	KM_UINT_REP = 4 << 28, /* Repeatable integer value */
	KM_ULONG = 5 << 28,
	KM_DATE = 6 << 28,
	KM_BOOL = 7 << 28,
	KM_BIGNUM = 8 << 28,
	KM_BYTES = 9 << 28,
	KM_ULONG_REP = 10 << 28, /* Repeatable long value */
} keymaster_tag_type_t;

typedef enum {
	KM_TAG_INVALID = KM_INVALID | 0,

	/*
	 * Tags that must be semantically enforced by hardware and software implementations.
	 */

	/* Crypto parameters */
	KM_TAG_PURPOSE = KM_ENUM_REP | 1,    /* keymaster_purpose_t. */
	KM_TAG_ALGORITHM = KM_ENUM | 2,      /* keymaster_algorithm_t. */
	KM_TAG_KEY_SIZE = KM_UINT | 3,       /* Key size in bits. */
	KM_TAG_BLOCK_MODE = KM_ENUM_REP | 4, /* keymaster_block_mode_t. */
	KM_TAG_DIGEST = KM_ENUM_REP | 5,     /* keymaster_digest_t. */
	KM_TAG_PADDING = KM_ENUM_REP | 6,    /* keymaster_padding_t. */
	KM_TAG_CALLER_NONCE = KM_BOOL | 7,   /* Allow caller to specify nonce or IV. */
	KM_TAG_MIN_MAC_LENGTH = KM_UINT | 8, /* Minimum length of MAC or AEAD authentication tag in
										  * bits. */
	KM_TAG_KDF = KM_ENUM_REP | 9,        /* keymaster_kdf_t (keymaster2) */
	KM_TAG_EC_CURVE = KM_ENUM | 10,      /* keymaster_ec_curve_t (keymaster2) */

	/* Algorithm-specific. */
	KM_TAG_RSA_PUBLIC_EXPONENT = KM_ULONG | 200,
	KM_TAG_ECIES_SINGLE_HASH_MODE = KM_BOOL | 201, /* Whether the ephemeral public key is fed into
													* the KDF */
	KM_TAG_INCLUDE_UNIQUE_ID = KM_BOOL | 202,      /* If true, attestation certificates for this key
													* will contain an application-scoped and
													* time-bounded device-unique ID. (keymaster2) */

	/* Other hardware-enforced. */
	KM_TAG_BLOB_USAGE_REQUIREMENTS = KM_ENUM | 301, /* keymaster_key_blob_usage_requirements_t */
	KM_TAG_BOOTLOADER_ONLY = KM_BOOL | 302,         /* Usable only by bootloader */

	/*
	 * Tags that should be semantically enforced by hardware if possible and will otherwise be
	 * enforced by software (keystore).
	 */

	/* Key validity period */
	KM_TAG_ACTIVE_DATETIME = KM_DATE | 400,             /* Start of validity */
	KM_TAG_ORIGINATION_EXPIRE_DATETIME = KM_DATE | 401, /* Date when new "messages" should no
														   longer be created. */
	KM_TAG_USAGE_EXPIRE_DATETIME = KM_DATE | 402,       /* Date when existing "messages" should no
														   longer be trusted. */
	KM_TAG_MIN_SECONDS_BETWEEN_OPS = KM_UINT | 403,     /* Minimum elapsed time between
														   cryptographic operations with the key. */
	KM_TAG_MAX_USES_PER_BOOT = KM_UINT | 404,           /* Number of times the key can be used per
														   boot. */

	/* User authentication */
	KM_TAG_ALL_USERS = KM_BOOL | 500,           /* Reserved for future use -- ignore */
	KM_TAG_USER_ID = KM_UINT | 501,             /* Reserved for future use -- ignore */
	KM_TAG_USER_SECURE_ID = KM_ULONG_REP | 502, /* Secure ID of authorized user or authenticator(s).
												   Disallowed if KM_TAG_ALL_USERS or
												   KM_TAG_NO_AUTH_REQUIRED is present. */
	KM_TAG_NO_AUTH_REQUIRED = KM_BOOL | 503,    /* If key is usable without authentication. */
	KM_TAG_USER_AUTH_TYPE = KM_ENUM | 504,      /* Bitmask of authenticator types allowed when
												 * KM_TAG_USER_SECURE_ID contains a secure user ID,
												 * rather than a secure authenticator ID.  Defined in
												 * hw_authenticator_type_t in hw_auth_token.h. */
	KM_TAG_AUTH_TIMEOUT = KM_UINT | 505,        /* Required freshness of user authentication for
												   private/secret key operations, in seconds.
												   Public key operations require no authentication.
												   If absent, authentication is required for every
												   use.  Authentication state is lost when the
												   device is powered off. */
	KM_TAG_ALLOW_WHILE_ON_BODY = KM_BOOL | 506, /* Allow key to be used after authentication timeout
												 * if device is still on-body (requires secure
												 * on-body sensor. */

	/* Application access control */
	KM_TAG_ALL_APPLICATIONS = KM_BOOL | 600, /* Specified to indicate key is usable by all
											  * applications. */
	KM_TAG_APPLICATION_ID = KM_BYTES | 601,  /* Byte string identifying the authorized
											  * application. */
	KM_TAG_EXPORTABLE = KM_BOOL | 602,       /* If true, private/secret key can be exported, but
											  * only if all access control requirements for use are
											  * met. (keymaster2) */

	/*
	 * Semantically unenforceable tags, either because they have no specific meaning or because
	 * they're informational only.
	 */
	KM_TAG_APPLICATION_DATA = KM_BYTES | 700,      /* Data provided by authorized application. */
	KM_TAG_CREATION_DATETIME = KM_DATE | 701,      /* Key creation time */
	KM_TAG_ORIGIN = KM_ENUM | 702,                 /* keymaster_key_origin_t. */
	KM_TAG_ROLLBACK_RESISTANT = KM_BOOL | 703,     /* Whether key is rollback-resistant. */
	KM_TAG_ROOT_OF_TRUST = KM_BYTES | 704,         /* Root of trust ID. */
	KM_TAG_OS_VERSION = KM_UINT | 705,             /* Version of system (keymaster2) */
	KM_TAG_OS_PATCHLEVEL = KM_UINT | 706,          /* Patch level of system (keymaster2) */
	KM_TAG_UNIQUE_ID = KM_BYTES | 707,             /* Used to provide unique ID in attestation */
	KM_TAG_ATTESTATION_CHALLENGE = KM_BYTES | 708, /* Used to provide challenge in attestation */

	/* Tags used only to provide data to or receive data from operations */
	KM_TAG_ASSOCIATED_DATA = KM_BYTES | 1000, /* Used to provide associated data for AEAD modes. */
	KM_TAG_NONCE = KM_BYTES | 1001,           /* Nonce or Initialization Vector */
	KM_TAG_AUTH_TOKEN = KM_BYTES | 1002,      /* Authentication token that proves secure user
												 authentication has been performed.  Structure
												 defined in hw_auth_token_t in hw_auth_token.h. */
	KM_TAG_MAC_LENGTH = KM_UINT | 1003,       /* MAC or AEAD authentication tag length in
											   * bits. */

	KM_TAG_RESET_SINCE_ID_ROTATION = KM_BOOL | 1004, /* Whether the device has beeen factory reset
														since the last unique ID rotation.  Used for
														key attestation. */
} keymaster_tag_t;

/**
 * Possible purposes of a key (or pair).
 */
typedef enum {
	KM_PURPOSE_ENCRYPT = 0,    /* Usable with RSA, EC and AES keys. */
	KM_PURPOSE_DECRYPT = 1,    /* Usable with RSA, EC and AES keys. */
	KM_PURPOSE_SIGN = 2,       /* Usable with RSA, EC and HMAC keys. */
	KM_PURPOSE_VERIFY = 3,     /* Usable with RSA, EC and HMAC keys. */
	KM_PURPOSE_DERIVE_KEY = 4, /* Usable with EC keys. */
} keymaster_purpose_t;

typedef struct {
	const uint8_t* data;
	size_t data_length;
} keymaster_blob_t;

typedef struct {
	keymaster_tag_t tag;
	union {
		uint32_t enumerated;   /* KM_ENUM and KM_ENUM_REP */
		bool boolean;          /* KM_BOOL */
		uint32_t integer;      /* KM_INT and KM_INT_REP */
		uint64_t long_integer; /* KM_LONG */
		uint64_t date_time;    /* KM_DATE */
		keymaster_blob_t blob; /* KM_BIGNUM and KM_BYTES*/
	} key_param;
} keymaster_key_param_t;

typedef struct {
	keymaster_key_param_t* params; /* may be NULL if length == 0 */
	size_t length;
} keymaster_key_param_set_t;

/**
 * Parameters that define a key's characteristics, including authorized modes of usage and access
 * control restrictions.  The parameters are divided into two categories, those that are enforced by
 * secure hardware, and those that are not.  For a software-only keymaster implementation the
 * enforced array must NULL.  Hardware implementations must enforce everything in the enforced
 * array.
 */
typedef struct {
	keymaster_key_param_set_t hw_enforced;
	keymaster_key_param_set_t sw_enforced;
} keymaster_key_characteristics_t;

typedef struct {
	const uint8_t* key_material;
	size_t key_material_size;
} keymaster_key_blob_t;

typedef struct {
	keymaster_blob_t* entries;
	size_t entry_count;
} keymaster_cert_chain_t;

/**
 * Formats for key import and export.
 */
typedef enum {
	KM_KEY_FORMAT_X509 = 0,  /* for public key export */
	KM_KEY_FORMAT_PKCS8 = 1, /* for asymmetric key pair import */
	KM_KEY_FORMAT_RAW = 3,   /* for symmetric key import and export*/
} keymaster_key_format_t;

/**
 * The keymaster operation API consists of begin, update, finish and abort. This is the type of the
 * handle used to tie the sequence of calls together.  A 64-bit value is used because it's important
 * that handles not be predictable.  Implementations must use strong random numbers for handle
 * values.
 */
typedef uint64_t keymaster_operation_handle_t;

typedef enum {
	KM_ERROR_OK = 0,
	KM_ERROR_ROOT_OF_TRUST_ALREADY_SET = -1,
	KM_ERROR_UNSUPPORTED_PURPOSE = -2,
	KM_ERROR_INCOMPATIBLE_PURPOSE = -3,
	KM_ERROR_UNSUPPORTED_ALGORITHM = -4,
	KM_ERROR_INCOMPATIBLE_ALGORITHM = -5,
	KM_ERROR_UNSUPPORTED_KEY_SIZE = -6,
	KM_ERROR_UNSUPPORTED_BLOCK_MODE = -7,
	KM_ERROR_INCOMPATIBLE_BLOCK_MODE = -8,
	KM_ERROR_UNSUPPORTED_MAC_LENGTH = -9,
	KM_ERROR_UNSUPPORTED_PADDING_MODE = -10,
	KM_ERROR_INCOMPATIBLE_PADDING_MODE = -11,
	KM_ERROR_UNSUPPORTED_DIGEST = -12,
	KM_ERROR_INCOMPATIBLE_DIGEST = -13,
	KM_ERROR_INVALID_EXPIRATION_TIME = -14,
	KM_ERROR_INVALID_USER_ID = -15,
	KM_ERROR_INVALID_AUTHORIZATION_TIMEOUT = -16,
	KM_ERROR_UNSUPPORTED_KEY_FORMAT = -17,
	KM_ERROR_INCOMPATIBLE_KEY_FORMAT = -18,
	KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM = -19,   /* For PKCS8 & PKCS12 */
	KM_ERROR_UNSUPPORTED_KEY_VERIFICATION_ALGORITHM = -20, /* For PKCS8 & PKCS12 */
	KM_ERROR_INVALID_INPUT_LENGTH = -21,
	KM_ERROR_KEY_EXPORT_OPTIONS_INVALID = -22,
	KM_ERROR_DELEGATION_NOT_ALLOWED = -23,
	KM_ERROR_KEY_NOT_YET_VALID = -24,
	KM_ERROR_KEY_EXPIRED = -25,
	KM_ERROR_KEY_USER_NOT_AUTHENTICATED = -26,
	KM_ERROR_OUTPUT_PARAMETER_NULL = -27,
	KM_ERROR_INVALID_OPERATION_HANDLE = -28,
	KM_ERROR_INSUFFICIENT_BUFFER_SPACE = -29,
	KM_ERROR_VERIFICATION_FAILED = -30,
	KM_ERROR_TOO_MANY_OPERATIONS = -31,
	KM_ERROR_UNEXPECTED_NULL_POINTER = -32,
	KM_ERROR_INVALID_KEY_BLOB = -33,
	KM_ERROR_IMPORTED_KEY_NOT_ENCRYPTED = -34,
	KM_ERROR_IMPORTED_KEY_DECRYPTION_FAILED = -35,
	KM_ERROR_IMPORTED_KEY_NOT_SIGNED = -36,
	KM_ERROR_IMPORTED_KEY_VERIFICATION_FAILED = -37,
	KM_ERROR_INVALID_ARGUMENT = -38,
	KM_ERROR_UNSUPPORTED_TAG = -39,
	KM_ERROR_INVALID_TAG = -40,
	KM_ERROR_MEMORY_ALLOCATION_FAILED = -41,
	KM_ERROR_IMPORT_PARAMETER_MISMATCH = -44,
	KM_ERROR_SECURE_HW_ACCESS_DENIED = -45,
	KM_ERROR_OPERATION_CANCELLED = -46,
	KM_ERROR_CONCURRENT_ACCESS_CONFLICT = -47,
	KM_ERROR_SECURE_HW_BUSY = -48,
	KM_ERROR_SECURE_HW_COMMUNICATION_FAILED = -49,
	KM_ERROR_UNSUPPORTED_EC_FIELD = -50,
	KM_ERROR_MISSING_NONCE = -51,
	KM_ERROR_INVALID_NONCE = -52,
	KM_ERROR_MISSING_MAC_LENGTH = -53,
	KM_ERROR_KEY_RATE_LIMIT_EXCEEDED = -54,
	KM_ERROR_CALLER_NONCE_PROHIBITED = -55,
	KM_ERROR_KEY_MAX_OPS_EXCEEDED = -56,
	KM_ERROR_INVALID_MAC_LENGTH = -57,
	KM_ERROR_MISSING_MIN_MAC_LENGTH = -58,
	KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH = -59,
	KM_ERROR_UNSUPPORTED_KDF = -60,
	KM_ERROR_UNSUPPORTED_EC_CURVE = -61,
	KM_ERROR_KEY_REQUIRES_UPGRADE = -62,
	KM_ERROR_ATTESTATION_CHALLENGE_MISSING = -63,
	KM_ERROR_KEYMASTER_NOT_CONFIGURED = -64,

	KM_ERROR_UNIMPLEMENTED = -100,
	KM_ERROR_VERSION_MISMATCH = -101,

	KM_ERROR_UNKNOWN_ERROR = -1000,
} keymaster_error_t;

static inline keymaster_tag_type_t keymaster_tag_get_type(keymaster_tag_t tag) {
	return (keymaster_tag_type_t)(tag & (0xF << 28));
}

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // ANDROID_OPTEE_TA_CA_DEFS_H

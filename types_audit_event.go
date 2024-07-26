package streamer

import (
	"time"

	"gorm.io/datatypes"
)

type With string

const (
	Saml                       With = "saml"
	TwoFactor                  With = "two-factor"
	TwoFactorViaWebauthnDevice With = "two-factor-via-webauthn-device"
)

type AuditEvent struct {
	ID            uint64 `gorm:"primary_key" json:"-"`
	CorrelationID string `gorm:"type:varchar(64);unique_index" json:"correlation_id"`

	Severity      string      `json:"severity"`
	Time          time.Time   `json:"time"`
	AuthorID      int64       `json:"author_id"`
	AuthorName    string      `json:"author_name"`
	EntityID      int64       `json:"entity_id"`
	EntityType    AuthorClass `json:"entity_type"`
	IPAddress     string      `json:"ip_address"`
	With          *With       `json:"with,omitempty"`
	TargetID      *int64      `json:"target_id"`
	TargetType    AuthorClass `json:"target_type"`
	TargetDetails *string     `json:"target_details"`
	EntityPath    string      `json:"entity_path"`
	Remove        *Add        `json:"remove,omitempty"`
	Add           *Add        `json:"add,omitempty"`
	// Details       *Details    `json:"details,omitempty"`
	// PushAccessLevels          []MergeAccessLevelElement `json:"push_access_levels,omitempty"`
	// MergeAccessLevels         []MergeAccessLevelElement `json:"merge_access_levels,omitempty"`
	AllowForcePush            *bool        `json:"allow_force_push,omitempty"`
	CodeOwnerApprovalRequired *bool        `json:"code_owner_approval_required,omitempty"`
	AuthorClass               *AuthorClass `json:"author_class,omitempty"`
	CustomMessage             *string      `json:"custom_message,omitempty"`
	As                        *As          `json:"as,omitempty"`
	MemberID                  *int64       `json:"member_id,omitempty"`
	Change                    *Change      `json:"change,omitempty"`
	From                      *string      `json:"from,omitempty"`
	To                        *string      `json:"to,omitempty"`
	Action                    *string      `json:"action,omitempty"`
	ExpiryFrom                *string      `json:"expiry_from"`
	ExpiryTo                  *string      `json:"expiry_to"`

	MetaCallerID        string `json:"meta.caller_id"`
	MetaRemoteIP        string `json:"meta.remote_ip"`
	MetaFeatureCategory string `json:"meta.feature_category"`
	MetaClientID        string `json:"meta.client_id"`
	MetaUser            string `json:"meta.user,omitempty"`
	MetaUserID          int    `json:"meta.user_id,omitempty"`

	OriginalData datatypes.JSON
}

// type Details struct {
// 	// PushAccessLevels          []MergeAccessLevelElement `json:"push_access_levels,omitempty"`
// 	// MergeAccessLevels         []MergeAccessLevelElement `json:"merge_access_levels,omitempty"`
// 	AllowForcePush            *bool       `json:"allow_force_push,omitempty"`
// 	CodeOwnerApprovalRequired *bool       `json:"code_owner_approval_required,omitempty"`
// 	AuthorName                string      `json:"author_name"`
// 	AuthorClass               AuthorClass `json:"author_class"`
// 	TargetID                  int64       `json:"target_id"`
// 	TargetType                AuthorClass `json:"target_type"`
// 	TargetDetails             string      `json:"target_details"`
// 	CustomMessage             string      `json:"custom_message"`
// 	IPAddress                 string      `json:"ip_address"`
// 	EntityPath                string      `json:"entity_path"`
// 	Change                    *Change     `json:"change,omitempty"`
// 	From                      *string     `json:"from,omitempty"`
// 	To                        *string     `json:"to,omitempty"`
// 	Action                    *string     `json:"action,omitempty"`
// 	Add                       *Add        `json:"add,omitempty"`
// }

type Add string

const (
	CiGroupVariable Add = "ci_group_variable"
	Email           Add = "email"
	Group           Add = "group"
	Project         Add = "project"
	User            Add = "user"
	UserAccess      Add = "user_access"
)

type As string

const (
	Developer As = "Developer"
	Guest     As = "Guest"
	Owner     As = "Owner"
)

type AuthorClass string

const (
	AuthorClassCiGroupVariable AuthorClass = "Ci::GroupVariable"
	AuthorClassEmail           AuthorClass = "Email"
	AuthorClassGroup           AuthorClass = "Group"
	AuthorClassProject         AuthorClass = "Project"
	AuthorClassUser            AuthorClass = "User"
	CiRunner                   AuthorClass = "Ci::Runner"
	PersonalAccessToken        AuthorClass = "PersonalAccessToken"
	ProtectedBranch            AuthorClass = "ProtectedBranch"
)

type Change string

const (
	AccessLevel   Change = "access_level"
	AllowedToPush Change = "allowed to push"
	EmailAddress  Change = "email address"
	Name          Change = "name"
)

type MergeAccessLevelElement string

const (
	Maintainers MergeAccessLevelElement = "Maintainers"
)

type Severity string

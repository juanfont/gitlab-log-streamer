package streamer

import (
	"time"

	"gorm.io/datatypes"
)

type AuthEvent struct {
	ID            uint64    `gorm:"primary_key" json:"-"`
	CorrelationID string    `gorm:"type:varchar(64)" json:"correlation_id"`
	Severity      string    `json:"severity"`
	Time          time.Time `json:"time"`

	Message              *string `json:"message,omitempty"`
	Env                  *string `json:"env,omitempty"`
	RemoteIP             *string `json:"remote_ip,omitempty"`
	RequestMethod        *string `json:"request_method,omitempty"`
	Path                 *string `json:"path,omitempty"`
	MetaCallerID         *string `json:"meta.caller_id,omitempty"`
	MetaRemoteIP         *string `json:"meta.remote_ip,omitempty"`
	MetaFeatureCategory  *string `json:"meta.feature_category,omitempty"`
	MetaClientID         *string `json:"meta.client_id,omitempty"`
	ScopeType            *string `json:"scope_type,omitempty"`
	RequestedProjectPath *string `json:"requested_project_path,omitempty"`
	// RequestedActions     []string `json:"requested_actions,omitempty"`
	// AuthorizedActions    []string `json:"authorized_actions,omitempty"`
	HTTPUser            *string `json:"http_user,omitempty"`
	AuthService         *string `json:"auth_service,omitempty"`
	AuthResultType      *string `json:"auth_result.type"`
	AuthResultActorType *string `json:"auth_result.actor_type"`
	PayloadType         *string `json:"payload_type,omitempty"`

	OriginalData datatypes.JSON
}

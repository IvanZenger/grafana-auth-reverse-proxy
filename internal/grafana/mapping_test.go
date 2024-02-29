package grafana

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSearchJsonForAttr(t *testing.T) {
	tests := []struct {
		name          string
		attributePath string
		data          string
		response      any
		expectedError error
	}{
		{
			name:          "Attributpath without dots",
			attributePath: "openid.email",
			data:          `{"openid": {"email": "hallo@email.ch"}}`,
			response:      "hallo@email.ch",
			expectedError: nil,
		},
		{
			name:          "role json",
			attributePath: "contains(groups[*], 'auth.strong') && 'Admin' || contains(groups[*], 'auth.strong') && 'Editor' || 'Viewer'",
			data:          `{"groups": ["auth.strong"]}`,
			response:      "Admin",
			expectedError: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attr, err := searchJSONForAttr(test.attributePath, []byte(test.data))

			if err != nil {
				fmt.Println(err)
			}
			require.Equal(t, test.response, attr)
			require.Equal(t, test.expectedError, err)
		})

	}
}

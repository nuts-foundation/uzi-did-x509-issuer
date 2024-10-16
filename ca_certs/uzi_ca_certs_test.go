package ca_certs

import (
	"testing"
)

func TestGetCertPools(t *testing.T) {
	// Define the test cases
	tests := []struct {
		name                    string
		includeTest             bool
		expectedRootLen         int
		expectedIntermediateLen int
		expectedError           error
	}{
		{
			name:                    "Test case 1: With Test Certificate included",
			includeTest:             true,
			expectedRootLen:         2,
			expectedIntermediateLen: 4,
			expectedError:           nil,
		},
		{
			name:                    "Test case 2: Without Test Certificate",
			includeTest:             false,
			expectedRootLen:         1,
			expectedIntermediateLen: 2,
			expectedError:           nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function we want to test
			root, intermediate, err := GetCertPools(tc.includeTest)

			if tc.expectedError != nil {
				// If we were expecting an error and we got one, then continue to next test case
				if err != nil {
					return
				}

				// If we were expecting an error and didn't get one, then report it
				t.Fatalf("expected error but got nil")
			}

			// Make sure we got what we expected
			if len(root.Subjects()) != tc.expectedRootLen || len(intermediate.Subjects()) != tc.expectedIntermediateLen {
				t.Errorf("expected root or intermediate certificate pools but got nil")
			}

		})
	}
}

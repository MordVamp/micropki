package serial

import (
	"testing"
)

func TestGenerateUniqueSerial(t *testing.T) {
	serial1, err := GenerateUniqueSerial()
	if err != nil {
		t.Fatalf("GenerateUniqueSerial failed: %v", err)
	}
	serial2, err := GenerateUniqueSerial()
	if err != nil {
		t.Fatalf("GenerateUniqueSerial failed: %v", err)
	}
	
	if serial1.Cmp(serial2) == 0 {
		t.Errorf("Serials should be unique")
	}
}

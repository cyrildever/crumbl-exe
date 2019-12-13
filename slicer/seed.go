package slicer

//--- TYPES

// Seed ...
type Seed int64

//--- METHODS

// SeedFor ...
func SeedFor(data string) Seed {
	var s int
	for _, char := range data {
		s += int(rune(char))
	}
	return Seed(s)
}

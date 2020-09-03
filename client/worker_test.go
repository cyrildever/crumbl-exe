package client_test

import (
	"os"
	"strings"
	"testing"

	"github.com/cyrildever/crumbl-exe/client"

	"gotest.tools/assert"
)

var dir, _ = getHomeDirectory()

// TestWorker ...
func TestWorker(t *testing.T) {
	ref := "cdever@edgewhere.fr"
	verificationHash := "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d"
	crumbled := "580fb8a91f05833200dea7d33536aaec99e56da492685aac67505a2e91e6f7040000a8BJmGgfjwAkIPs2rPt1y3mRZzx+f/o/cs7IBhaRb0SyxwsHvL1SKx+yH4HQU6ZK30h1Dtbwpx0HkIEqjfg4gWmFqNOQTHm4Ry+XdN6Aucrt0CpHPCSNc8mA0sQa9STKM89M4XQ46Mf1AJ8oWpyV5AvmmM7SULvJA8oS7UXwE=0100a8BEq0u3vV/c/wS2IrN2ph+HLAGG8AHk8o5tlOCJ8osXDWaej+0DeksO78Y0dVilcIDnHQv7P5Rhpcj+N8dHSrul5s1aRkSuu4nSY6bk9Tev4mCKWRFVpwUWaPBPPxK+j/hgCk4/hDPUU2bV/egmyKTOJijuNS/ebEmwTpUXU=0200a8BEGzuG7r4DZ3DHW6g851iAL3Vf+L4GV/8kQdDHrVdFJn/zhkrD7AM2LS+BmJ9dl3M3omMwuG+RDtzbjfRo7Lfpa3WgQBWARgHgpCzJIO8DCbEDLP0u4BcHOQtxW1cGu/ChSMCx/VhaIxj8TWQ7AdonjCUWxMtI39KerQUHk=.1"
	partialUncrumb1 := "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%01AgICBFUDDk4PXEc=.1"
	partialUncrumb2 := "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%02AgICAgICAgkYUkI=.1"

	worker := client.CrumblWorker{
		Mode:             client.EXTRACTION,
		OwnerKeys:        "ecies:" + dir + "crypto/ecies/keys/owner1.pub",
		OwnerSecret:      dir + "crypto/ecies/keys/owner1.sk",
		VerificationHash: verificationHash,
		Data:             []string{crumbled, partialUncrumb1, partialUncrumb2},
	}
	result, err := worker.Process(true)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, result, ref)
}

func getHomeDirectory() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return strings.Replace(dir, "client", "", 1), nil
}

// TestWorker2 ...
func TestWorker2(t *testing.T) {
	ref := "cyril@dever.com"
	verificationHash := "cc8b00be1cc7592806ba4f8fe4411d3744121dc12e6201dc36e873f7fd9a6bae"
	crumbled := "cc8b00be1cc7592806ba4f8fe4411d374064d57e96845c04ed360d0901d64b7a0000a4BHbIv7jmXdjb3n7+/Ewg1Br4EXYksmb4RmavTQsDVJAFY/he1rs7gpRY9+waPCww3YMzr5IIWFYN8LDVDDxV2bdTGBNjHWbsb4WRM2ItLFVYubxBto/6pfGyXJ0ZriYjL2RCVtPw8cdJrkeXqSqOEz1ICBTN9UOBZw==0000a4BLaggeNjl7tsFhAymEipkuIco8xG8trm6E+4WzrTX7spC0DmdyTFhU8enJV2WERxOaF7iy6E64/2+2wIL/MqRMnyRnJJJDab6d7pTWMSEVOUAvEFugTP95XpnnZcDyzLdZ2J+YBbMYtRcnxH4TJA9AIwksl0oJRA/w==0100a4BJOU/0Jo239EUuDd6Lxu8gRICsND71bSg+qY3n1n7o/EA+d5g6orQnpw4Zr5QnfNQIUxgMCmNqI/rY5EpsR+emtHVIF6OS+1cgKhkwhbBHrNRZDsnOvH3XBVrIOk6CpEm1+hPRNt1E6h6zFr7EfDenRhE0RxWth42g==0100a4BPKEPk14AeNPSiPos2Ob5wML/1Oyn3zJDXdKr9nCEct7HhSGu348ESZrhbp14nsNEihbrh6tzOOj11KqfJWeq7PEROAnynm9K2fLp6rl7o1vwAgW5f+4a/7tzn3rH8XkoHbamHfAU1GGYwop1QPFvXhr+FC8SKwuuQ==0200a4BFq+ZlkogXqxBDlTZvMZbCEqi6F480LSEZioZLcj8aGBmT2c+yzY2DR66+KinG1qaYQ+rGRRenMut+dcuRIKbVA5tNZYXJAWBtL3mStYpaDWqYBTIG06Ml3tjpD4+Jr3xgI0lmczL53CUm0SzL7eXaBbxMtQmcfg6Q==0200a4BIq9Hdb9zuSd+YwNwD9kUXuY0RogGe6NNWfpXhhbmbCGM/mhuX9qegKotLit7Ws0osggpVLSQ9b2yV8krH5DUToJNuxdCiRTvKMtgMJpWtDbYuV3yxoITb2azq7u9G2SVkWGaqXUsAupe9si7nIc4maeufh1vXkgWA==0300a4BLHdrR+dhbUfm9O5LByNZfXmJIpEGr2yy6+nyQG1GtLpdMLbUrzStYExEoAfQPuPtpKZmyWCBHleVQVrF71mPBjeiTCLyyuLm6qMXJ6lxQ0D/7jUcKQX6vUymtnEevw0326nD/lobnxp65lhg30cnDsYngT5+AeKSw==0300a4BAhTnL9o/IxxAyVqoal6hn9JlwZCn+SDnuBkhH4fCBrOC+btqM/D3NIDcR1+Zdiy55k9doYtiaeYcdvKGlXbwE3rwK94heEHgEzTysX18ciduFMpgoc1x0aY7MfUipyEw5y5165NFhX6U3lZJ7501AU9kAZ3iHAePA==.1"
	partialUncrumb1 := "cc8b00be1cc7592806ba4f8fe4411d3744121dc12e6201dc36e873f7fd9a6bae%01AgICfVkLEVU=%02AgICAhhHVw8=.1"
	partialUncrumb2 := "cc8b00be1cc7592806ba4f8fe4411d3744121dc12e6201dc36e873f7fd9a6bae%02AgICAhhHVw8=%03AgICAgICAgE=.1"

	// obfuscated, _ := obfuscator.Obfuscator{
	// 	Key:    obfuscator.DEFAULT_KEY_STRING,
	// 	Rounds: obfuscator.DEFAULT_ROUNDS,
	// }.Apply("cyril@dever.com")
	// fmt.Println("obfuscated", len(obfuscated), obfuscated)

	// numberOfSlices := 4
	// deltaMax := slicer.GetDeltaMax(len(obfuscated), numberOfSlices)
	// slices, _ := slicer.Slicer{
	// 	NumberOfSlices: numberOfSlices,
	// 	DeltaMax:       deltaMax,
	// }.Apply(utils.LeftPad(string(obfuscated), slicer.MIN_INPUT_SIZE))
	// fmt.Println("slices", len(slices))
	// for _, slice := range slices {
	// 	fmt.Println(slice)
	// 	for _, c := range slice {
	// 		fmt.Printf("\\u00%02d", c)
	// 	}
	// }

	// signer := client.CrumblWorker{
	// 	Mode:             client.EXTRACTION,
	// 	SignerKeys:       "ecies:" + dir + "crypto/ecies/keys/signer.pub",
	// 	SignerSecret:     dir + "crypto/ecies/keys/signer.sk",
	// 	VerificationHash: verificationHash,
	// 	Data:             []string{crumbled},
	// }
	// partialUncrumb, err := signer.Process(true)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// assert.Equal(t, partialUncrumb, partialUncrumb2)

	worker := client.CrumblWorker{
		Mode:             client.EXTRACTION,
		OwnerKeys:        "ecies:" + dir + "crypto/ecies/keys/emitter.pub",
		OwnerSecret:      dir + "crypto/ecies/keys/emitter.sk",
		VerificationHash: verificationHash,
		Data:             []string{crumbled, partialUncrumb1, partialUncrumb2},
	}
	result, err := worker.Process(true)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, result, ref)
}

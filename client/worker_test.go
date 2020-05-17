package client_test

import (
	"os"
	"strings"
	"testing"

	"github.com/edgewhere/crumbl-exe/client"

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

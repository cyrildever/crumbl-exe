package client_test

import (
	"crumbl/client"
	"os"
	"strings"
	"testing"

	"gotest.tools/assert"
)

var dir, _ = getHomeDirectory()

// TestWorker ...
func TestWorker(t *testing.T) {
	ref := "cdever@edgewhere.fr"
	verificationHash := "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d"
	crumbled := "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d0000a8BJM2I8mS/bkFNdZOATg8jHsQbzYp4o5rTqYWkf/pqgvkH7a4OijBxy86W1y2J+pB525jYO4iBuig2JswBdNv++8dkb0GcSXT873M0I5Xma9oM83eHXihOF2rqnqWN/RNZPwJSM23DcCj/xyVs1FK5jWVMGxtMLttIN7vqg==010158KbcQ6boXhkGdXR97+UwSHvt12wEwkVa57e+2m+66sTu32luP00cWET2gb01tgNZYjU621U7u4RI6fmz5kkyTSZtjPJ5wXISTf2wOBv5cY94LvgYoyMFKP9J3mGbPgAKGGsIdY4GCQBx6+Gi7VzfuNxdP1YHAPqcpKXPWiY+nmqYhT7eZVZlmNF1UmkMbgrneYglenmKxWSyUA6P7yMj3LrhlKekWAPdWpMLzRftLh1oH5e2KHkz7Wyh9eYOCKXlQ4sUUm8o3i0Inann41wL0KGaNajPU1RP0M9n3/Zil1/T+ZZcNJgSlQh1mxVKX1ztBRqYNUy+pqDat1qq6ED5r5A==0200a8BIIMyYgouCq7ZVy7S1kRJUl1Lg+aQMHoNeo7SauKwsy//XZ5rJOF4FrYMXmPpu0pf7nwCgAgk6Iv9IQK+WXsKpDE+QazdPpYFtxm4/1qi8qnzG1Wp/9Lf5nFTozacHqghz2e7XkaO1qyLNfmzimpsm6aw/lhEsd+djJ8KA==.1"
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

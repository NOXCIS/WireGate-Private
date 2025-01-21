package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	tcPath       = "/sbin/tc"
	wgPath       = "/usr/bin/wg"
	awgPath      = "/usr/bin/awg"                // AmneziaWG path
	protocolPath = "/tmp/wiregate_protocol.json" // Temporary file for protocol info
)

type PeerInfo struct {
	PublicKey  string
	AllowedIPs []string
}

type ProtocolInfo struct {
	Protocol string `json:"protocol"`
}

// getProtocolFromConfig reads the protocol from the temporary file written by Python
func getProtocolFromConfig() (string, error) {
	data, err := os.ReadFile(protocolPath)
	if err != nil {
		return "", fmt.Errorf("failed to read protocol info: %v", err)
	}

	var info ProtocolInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return "", fmt.Errorf("failed to parse protocol info: %v", err)
	}

	return info.Protocol, nil
}

func main() {
	// Define command line flags
	interfaceName := flag.String("interface", "", "WireGuard interface name (required)")
	peerKey := flag.String("peer", "", "WireGuard peer public key (required)")
	rateLimit := flag.Int("rate", 0, "Rate limit in Kb/s (required)")
	flag.Parse()

	fmt.Printf("Starting traffic-weir with interface=%s, peer=%s, rate=%d\n",
		*interfaceName, *peerKey, *rateLimit)

	if *interfaceName == "" || *peerKey == "" || *rateLimit == 0 {
		fmt.Println("Error: All flags are required")
		flag.Usage()
		os.Exit(1)
	}

	// Check if tc is available
	if _, err := exec.LookPath(tcPath); err != nil {
		fmt.Printf("Error: tc command not found at %s. Please install iproute2.\n", tcPath)
		os.Exit(1)
	}

	fmt.Println("Reading protocol configuration...")
	protocol, err := getProtocolFromConfig()
	if err != nil {
		fmt.Printf("Error getting protocol: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Using protocol: %s\n", protocol)

	// Get peer information using the appropriate protocol command
	fmt.Printf("Fetching peer information for %s...\n", *peerKey)
	var peerInfo *PeerInfo
	switch protocol {
	case "wg":
		peerInfo, err = getWgPeerInfo(*interfaceName, *peerKey)
	case "awg":
		peerInfo, err = getAwgPeerInfo(*interfaceName, *peerKey)
	default:
		fmt.Printf("Error: Unsupported protocol %s\n", protocol)
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("Error getting peer information: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found peer with %d allowed IPs\n", len(peerInfo.AllowedIPs))

	if len(peerInfo.AllowedIPs) == 0 {
		fmt.Printf("Error: No allowed IPs found for peer %s\n", *peerKey)
		os.Exit(1)
	}

	// Clean up existing qdisc
	fmt.Println("Cleaning up existing traffic control rules...")
	cleanupCmd := exec.Command(tcPath, "qdisc", "del", "dev", *interfaceName, "root")
	if err := cleanupCmd.Run(); err != nil {
		fmt.Printf("Note: Cleanup returned: %v (this is usually safe to ignore)\n", err)
	}

	// Create root qdisc
	fmt.Println("Setting up root qdisc...")
	if err := setupRootQdisc(*interfaceName); err != nil {
		fmt.Printf("Error setting up root qdisc: %v\n", err)
		os.Exit(1)
	}

	// Create class for peer
	fmt.Printf("Creating rate limit class (%d Kb/s)...\n", *rateLimit)
	classID := "1:10"
	err = createOrUpdateRateLimitClass(*interfaceName, classID, *rateLimit)
	if err != nil {
		fmt.Printf("Error creating rate limit class: %v\n", err)
		os.Exit(1)
	}

	// Add filters for each IP
	fmt.Println("Setting up filters for allowed IPs...")
	for _, ip := range peerInfo.AllowedIPs {
		fmt.Printf("Adding filters for IP %s...\n", ip)
		if err := addFiltersForIP(*interfaceName, classID, ip); err != nil {
			fmt.Printf("Error setting up rate limit for IP %s: %v\n", ip, err)
			continue
		}
		fmt.Printf("Successfully set rate limit of %d Kb/s for IP %s\n", *rateLimit, ip)
	}

	fmt.Printf("Successfully configured rate limiting for peer %s on interface %s\n",
		*peerKey, *interfaceName)
}

func setupRootQdisc(iface string) error {
	cmd := exec.Command(tcPath, "qdisc", "add", "dev", iface,
		"root", "handle", "1:", "htb", "default", "99")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add root qdisc: %v\nOutput: %s", err, output)
	}
	return nil
}

func createOrUpdateRateLimitClass(iface, classID string, rateKbps int) error {
	// Try to modify existing class first
	modifyCmd := exec.Command(tcPath, "class", "change", "dev", iface,
		"parent", "1:", "classid", classID,
		"htb", "rate", fmt.Sprintf("%dkbit", rateKbps),
		"burst", "15k", "ceil", fmt.Sprintf("%dkbit", rateKbps))

	if err := modifyCmd.Run(); err != nil {
		// If modification failed (class doesn't exist), create new class
		createCmd := exec.Command(tcPath, "class", "add", "dev", iface,
			"parent", "1:", "classid", classID,
			"htb", "rate", fmt.Sprintf("%dkbit", rateKbps),
			"burst", "15k", "ceil", fmt.Sprintf("%dkbit", rateKbps))

		output, err := createCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to add traffic class: %v\nOutput: %s", err, output)
		}
	}
	return nil
}

func applyRateLimitForPeer(iface string, peer *PeerInfo, rateLimit int) error {
	// Check if root qdisc exists
	checkCmd := exec.Command(tcPath, "qdisc", "show", "dev", iface)
	output, _ := checkCmd.CombinedOutput()

	if !strings.Contains(string(output), "htb 1:") {
		// Create root qdisc only if it doesn't exist
		if err := setupRootQdisc(iface); err != nil {
			return fmt.Errorf("failed to setup root qdisc: %v", err)
		}
	}

	// Create or update rate limit class
	classID := "1:10"
	if err := createOrUpdateRateLimitClass(iface, classID, rateLimit); err != nil {
		return fmt.Errorf("failed to create/update rate limit class: %v", err)
	}

	// Check existing filters
	checkFiltersCmd := exec.Command(tcPath, "filter", "show", "dev", iface)
	filterOutput, _ := checkFiltersCmd.CombinedOutput()

	// Add filters only if they don't exist
	for _, ip := range peer.AllowedIPs {
		if !strings.Contains(string(filterOutput), ip) {
			if err := addFiltersForIP(iface, classID, ip); err != nil {
				return fmt.Errorf("failed to add filters for IP %s: %v", ip, err)
			}
		}
	}

	return nil
}

func addFiltersForIP(iface, classID, ipCIDR string) error {
	maxRetries := 3
	retryDelay := time.Second * 2

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			fmt.Printf("Retry attempt %d/%d for IP %s...\n", attempt, maxRetries, ipCIDR)
		}

		err := tryAddFiltersForIP(iface, classID, ipCIDR)
		if err == nil {
			return nil
		}

		fmt.Printf("Attempt %d failed: %v\n", attempt, err)
		if attempt < maxRetries {
			fmt.Printf("Waiting %v before retry...\n", retryDelay)
			time.Sleep(retryDelay)
			continue
		}
		return fmt.Errorf("failed to add filters after %d attempts: %v", maxRetries, err)
	}
	return nil
}

func tryAddFiltersForIP(iface, classID, ipCIDR string) error {
	ipOnly := strings.Split(ipCIDR, "/")[0]
	protocol := "ip"
	if strings.Contains(ipOnly, ":") {
		protocol = "ipv6"
	}

	fmt.Printf("Setting up %s filters for %s...\n", protocol, ipOnly)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Outgoing traffic filter
	fmt.Println("Adding outgoing traffic filter...")
	filterCmd := exec.CommandContext(ctx, tcPath, "filter", "add", "dev", iface,
		"protocol", protocol, "parent", "1:", "prio", "1",
		"u32", "match", "ip", "src", ipOnly,
		"flowid", classID)
	if output, err := filterCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add outgoing filter: %v\nOutput: %s", err, output)
	}

	// Incoming traffic filter
	fmt.Println("Adding incoming traffic filter...")
	filterCmd = exec.CommandContext(ctx, tcPath, "filter", "add", "dev", iface,
		"protocol", protocol, "parent", "1:", "prio", "1",
		"u32", "match", "ip", "dst", ipOnly,
		"flowid", classID)
	if output, err := filterCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add incoming filter: %v\nOutput: %s", err, output)
	}

	fmt.Printf("Successfully added both filters for %s\n", ipOnly)
	return nil
}

// getPeerInfo tries 'wg show' first, then 'awg show'
func getPeerInfo(interfaceName, peerKey string) (*PeerInfo, error) {
	info, err := getWgPeerInfo(interfaceName, peerKey)
	if err == nil {
		return info, nil
	}
	info, err = getAwgPeerInfo(interfaceName, peerKey)
	if err == nil {
		return info, nil
	}
	return nil, fmt.Errorf("peer not found in either wg or awg")
}

func getWgPeerInfo(interfaceName, peerKey string) (*PeerInfo, error) {
	cmd := exec.Command(wgPath, "show", interfaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute wg show: %v", err)
	}
	return parsePeerInfo(string(output), peerKey)
}

func getAwgPeerInfo(interfaceName, peerKey string) (*PeerInfo, error) {
	cmd := exec.Command(awgPath, "show", interfaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute awg show: %v", err)
	}
	return parsePeerInfo(string(output), peerKey)
}

func parsePeerInfo(output, targetPeerKey string) (*PeerInfo, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	peer := &PeerInfo{AllowedIPs: make([]string, 0)}

	foundPeer := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "peer:") || strings.HasPrefix(line, "public key:") {
			key := strings.TrimSpace(strings.Split(line, ":")[1])
			if key == targetPeerKey {
				foundPeer = true
				peer.PublicKey = key
			} else {
				foundPeer = false
			}
		} else if foundPeer && strings.HasPrefix(line, "allowed ips:") {
			ips := strings.Split(strings.TrimSpace(strings.Split(line, ":")[1]), ",")
			for _, ip := range ips {
				ip = strings.TrimSpace(ip)
				if ip != "" {
					peer.AllowedIPs = append(peer.AllowedIPs, ip)
				}
			}
		}
	}

	if !foundPeer {
		return nil, fmt.Errorf("peer not found")
	}
	return peer, nil
}

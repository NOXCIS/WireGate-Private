package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	tcPath  = "/sbin/tc"
	wgPath  = "/usr/bin/wg"
	awgPath = "/usr/bin/awg" // AmneziaWG path
)

type PeerInfo struct {
	PublicKey  string
	AllowedIPs []string
}

func main() {
	var (
		iface        string
		peer         string
		uploadRate   int
		downloadRate int
		protocol     string
		remove       bool
	)

	flag.StringVar(&iface, "interface", "", "Interface name")
	flag.StringVar(&peer, "peer", "", "Peer ID")
	flag.IntVar(&uploadRate, "upload-rate", 0, "Upload rate limit in KB/s")
	flag.IntVar(&downloadRate, "download-rate", 0, "Download rate limit in KB/s")
	flag.StringVar(&protocol, "protocol", "wg", "Protocol (wg or awg)")
	flag.BoolVar(&remove, "remove", false, "Remove rate limits")
	flag.Parse()

	fmt.Printf("Starting traffic-weir with interface=%s, peer=%s, upload-rate=%d, download-rate=%d, protocol=%s, remove=%v\n",
		iface, peer, uploadRate, downloadRate, protocol, remove)

	if iface == "" || peer == "" || protocol == "" {
		fmt.Println("Error: interface, peer, and protocol flags are required")
		flag.Usage()
		os.Exit(1)
	}

	if !remove && uploadRate == 0 && downloadRate == 0 {
		fmt.Println("Error: at least one of upload-rate or download-rate must be specified unless -remove is used")
		flag.Usage()
		os.Exit(1)
	}

	if protocol != "wg" && protocol != "awg" {
		fmt.Printf("Error: Invalid protocol %s. Must be either 'wg' or 'awg'\n", protocol)
		os.Exit(1)
	}

	// Check if tc is available
	if _, err := exec.LookPath(tcPath); err != nil {
		fmt.Printf("Error: tc command not found at %s. Please install iproute2.\n", tcPath)
		os.Exit(1)
	}

	if remove {
		fmt.Printf("Removing rate limits for peer %s on interface %s...\n", peer, iface)
		if err := removeRateLimits(iface); err != nil {
			fmt.Printf("Error removing rate limits: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Successfully removed rate limits")
		os.Exit(0)
	}

	// Get peer information using the specified protocol
	fmt.Printf("Fetching peer information for %s...\n", peer)
	var peerInfo *PeerInfo
	var err error
	switch protocol {
	case "wg":
		peerInfo, err = getWgPeerInfo(iface, peer)
	case "awg":
		peerInfo, err = getAwgPeerInfo(iface, peer)
	}

	if err != nil {
		fmt.Printf("Error getting peer information: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found peer with %d allowed IPs\n", len(peerInfo.AllowedIPs))

	if len(peerInfo.AllowedIPs) == 0 {
		fmt.Printf("Error: No allowed IPs found for peer %s\n", peer)
		os.Exit(1)
	}

	// Clean up existing qdisc
	fmt.Println("Cleaning up existing traffic control rules...")
	cleanupCmd := exec.Command(tcPath, "qdisc", "del", "dev", iface, "root")
	if err := cleanupCmd.Run(); err != nil {
		fmt.Printf("Note: Cleanup returned: %v (this is usually safe to ignore)\n", err)
	}

	// Create root qdisc
	fmt.Println("Setting up root qdisc...")
	if err := setupRootQdisc(iface); err != nil {
		fmt.Printf("Error setting up root qdisc: %v\n", err)
		os.Exit(1)
	}

	// Create separate classes for upload and download
	classBase := peerToClassID(peer)
	uploadClassID := fmt.Sprintf("1:%d1", classBase)   // Add '1' suffix for upload
	downloadClassID := fmt.Sprintf("1:%d2", classBase) // Add '2' suffix for download

	if uploadRate > 0 {
		if err := createClass(iface, uploadClassID, uploadRate); err != nil {
			fmt.Printf("Error creating upload rate limit class: %v\n", err)
			os.Exit(1)
		}
	}

	if downloadRate > 0 {
		if err := createClass(iface, downloadClassID, downloadRate); err != nil {
			fmt.Printf("Error creating download rate limit class: %v\n", err)
			os.Exit(1)
		}
	}

	// Now use the defined class IDs
	if err := tryAddFiltersForIP(iface, uploadClassID, peerInfo.AllowedIPs[0], uploadRate, 0); err != nil {
		fmt.Printf("Error setting up upload rate limits for peer %s: %v\n", peer, err)
		os.Exit(1)
	}

	if err := tryAddFiltersForIP(iface, downloadClassID, peerInfo.AllowedIPs[0], 0, downloadRate); err != nil {
		fmt.Printf("Error setting up download rate limits for peer %s: %v\n", peer, err)
		os.Exit(1)
	}

	fmt.Printf("Successfully configured rate limiting for peer %s on interface %s\n",
		peer, iface)
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

func createClass(iface, classID string, rateKbps int) error {
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

func tryAddFiltersForIP(iface, classID, peer string, uploadRate, downloadRate int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Extract IP from CIDR notation
	ipOnly := strings.Split(peer, "/")[0]
	protocol := "ip"
	if strings.Contains(ipOnly, ":") {
		protocol = "ipv6"
	}

	if uploadRate > 0 {
		// Outgoing traffic filter (upload)
		filterCmd := exec.CommandContext(ctx, tcPath, "filter", "add", "dev", iface,
			"protocol", protocol, "parent", "1:", "prio", "1",
			"u32", "match", "ip", "src", ipOnly,
			"flowid", classID)
		if err := filterCmd.Run(); err != nil {
			return fmt.Errorf("failed to add upload filter: %v", err)
		}
	}

	if downloadRate > 0 {
		// Incoming traffic filter (download)
		filterCmd := exec.CommandContext(ctx, tcPath, "filter", "add", "dev", iface,
			"protocol", protocol, "parent", "1:", "prio", "1",
			"u32", "match", "ip", "dst", ipOnly,
			"flowid", classID)
		if err := filterCmd.Run(); err != nil {
			return fmt.Errorf("failed to add download filter: %v", err)
		}
	}

	return nil
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

		// Make parsing more flexible by handling different key formats
		if strings.Contains(line, targetPeerKey) {
			foundPeer = true
			peer.PublicKey = targetPeerKey
			continue
		}

		// Only process allowed IPs if we've found our peer
		if foundPeer && (strings.Contains(line, "allowed ip") || strings.Contains(line, "allowed_ip")) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ips := strings.Split(strings.TrimSpace(parts[1]), ",")
				for _, ip := range ips {
					ip = strings.TrimSpace(ip)
					if ip != "" {
						peer.AllowedIPs = append(peer.AllowedIPs, ip)
					}
				}
			}
		}
	}

	if !foundPeer {
		// Add more detailed error message
		return nil, fmt.Errorf("peer not found in output: %s", output)
	}
	return peer, nil
}

func removeRateLimits(iface string) error {
	// Clean up existing qdisc which removes all rate limits
	fmt.Println("Removing traffic control rules...")
	cleanupCmd := exec.Command(tcPath, "qdisc", "del", "dev", iface, "root")
	output, err := cleanupCmd.CombinedOutput()
	if err != nil {
		// Check if the error is because there were no rules to remove
		if strings.Contains(string(output), "RTNETLINK answers: No such file or directory") {
			fmt.Println("No existing traffic control rules found")
			return nil
		}
		return fmt.Errorf("failed to remove traffic control rules: %v\nOutput: %s", err, output)
	}
	return nil
}

func peerToClassID(peer string) int {
	// Simple hash function to generate a class ID from peer key
	var hash uint32
	for i := 0; i < len(peer); i++ {
		hash = hash*31 + uint32(peer[i])
	}
	return int(hash%90) + 10 // Range 10-99 to ensure valid class IDs
}

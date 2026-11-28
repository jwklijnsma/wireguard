//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Adapted for wg2fa: only the DNS leak block is installed, not the full
 * kill switch.
 */

// Package wfp installs Windows Filtering Platform filters that stop DNS
// queries from leaving outside the tunnel. It is a trimmed copy of
// golang.zx2c4.com/wireguard/windows/tunnel/firewall (MIT).
//
// The filters live in a dynamic WFP session: they disappear automatically
// when the session is closed or the process exits (including a crash), so a
// dead client can never leave the machine without DNS.
package wfp

import (
	"errors"
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wfpObjectInstaller func(uintptr) error

// Fundamental wg2fa specific WFP objects.
type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

var (
	mu         sync.Mutex
	wfpSession uintptr
)

func createWfpSession() (uintptr, error) {
	sessionDisplayData, err := createWtFwpmDisplayData0("WG2FA", "WG2FA dynamic session")
	if err != nil {
		return 0, wrapErr(err)
	}
	session := wtFwpmSession0{
		displayData:          *sessionDisplayData,
		flags:                cFWPM_SESSION_FLAG_DYNAMIC,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}
	sessionHandle := uintptr(0)
	err = fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&sessionHandle))
	if err != nil {
		return 0, wrapErr(err)
	}
	return sessionHandle, nil
}

func registerBaseObjects(session uintptr) (*baseObjects, error) {
	bo := &baseObjects{}
	var err error
	if bo.provider, err = windows.GenerateGUID(); err != nil {
		return nil, wrapErr(err)
	}
	if bo.filters, err = windows.GenerateGUID(); err != nil {
		return nil, wrapErr(err)
	}
	displayData, err := createWtFwpmDisplayData0("WG2FA", "WG2FA provider")
	if err != nil {
		return nil, wrapErr(err)
	}
	provider := wtFwpmProvider0{providerKey: bo.provider, displayData: *displayData}
	if err = fwpmProviderAdd0(session, &provider, 0); err != nil {
		return nil, wrapErr(err)
	}
	displayData, err = createWtFwpmDisplayData0("WG2FA filters", "DNS leak protection")
	if err != nil {
		return nil, wrapErr(err)
	}
	sublayer := wtFwpmSublayer0{
		subLayerKey: bo.filters,
		displayData: *displayData,
		providerKey: &bo.provider,
		weight:      ^uint16(0),
	}
	if err = fwpmSubLayerAdd0(session, &sublayer, 0); err != nil {
		return nil, wrapErr(err)
	}
	return bo, nil
}

// BlockDNS blocks port 53 (UDP and TCP, IPv4 and IPv6) to every address
// except dnsServers, which are the resolvers pushed through the tunnel.
// The calling process itself stays exempt so it can still resolve the VPN
// endpoint. Requires administrator / SYSTEM rights.
func BlockDNS(dnsServers []netip.Addr) error {
	if len(dnsServers) == 0 {
		return errors.New("no DNS servers to allow")
	}
	mu.Lock()
	defer mu.Unlock()
	if wfpSession != 0 {
		return errors.New("DNS block already active")
	}
	session, err := createWfpSession()
	if err != nil {
		return wrapErr(err)
	}
	err = runTransaction(session, func(session uintptr) error {
		bo, err := registerBaseObjects(session)
		if err != nil {
			return wrapErr(err)
		}
		if err := permitWireGuardService(session, bo, 15); err != nil {
			return wrapErr(err)
		}
		return blockDNS(dnsServers, session, bo, 15, 14)
	})
	if err != nil {
		fwpmEngineClose0(session)
		return wrapErr(err)
	}
	wfpSession = session
	return nil
}

// Unblock removes the filters installed by BlockDNS. Safe to call twice.
func Unblock() {
	mu.Lock()
	defer mu.Unlock()
	if wfpSession != 0 {
		fwpmEngineClose0(wfpSession)
		wfpSession = 0
	}
}

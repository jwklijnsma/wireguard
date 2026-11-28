//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package wfp

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"runtime"
	"unsafe"
)

func permitWireGuardService(session uintptr, baseObjects *baseObjects, weight uint8) error {
	var conditions [2]wtFwpmFilterCondition0

	//
	// First condition is the exe path of the current process.
	//
	appID, err := getCurrentProcessAppID()
	if err != nil {
		return wrapErr(err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))

	conditions[0] = wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_BYTE_BLOB_TYPE,
			value: uintptr(unsafe.Pointer(appID)),
		},
	}

	//
	// Second condition is the SECURITY_DESCRIPTOR of the current process.
	// This prevents other processes hosted in the same exe from matching this filter.
	//
	sd, err := getCurrentProcessSecurityDescriptor()
	if err != nil {
		return wrapErr(err)
	}

	sdBlob := wtFwpByteBlob{sd.Length(), (*byte)(unsafe.Pointer(sd))}
	conditions[1] = wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_USER_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_SECURITY_DESCRIPTOR_TYPE,
			value: uintptr(unsafe.Pointer(&sdBlob)),
		},
	}

	//
	// Assemble the filter.
	//
	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted outbound traffic for WireGuard service (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted inbound traffic for WireGuard service (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted outbound traffic for WireGuard service (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted inbound traffic for WireGuard service (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	runtime.KeepAlive(sdBlob)
	runtime.KeepAlive(sd)
	return nil
}

func blockDNS(except []netip.Addr, session uintptr, baseObjects *baseObjects, weightAllow, weightDeny uint8) error {
	if weightDeny >= weightAllow {
		return errors.New("The allow weight must be greater than the deny weight")
	}

	denyConditions := []wtFwpmFilterCondition0{
		{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_PORT,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT16,
				value: uintptr(53),
			},
		},
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(cIPPROTO_UDP),
			},
		},
		// Repeat the condition type for logical OR.
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(cIPPROTO_TCP),
			},
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weightDeny),
		numFilterConditions: uint32(len(denyConditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&denyConditions[0])),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK,
		},
	}

	filterID := uint64(0)

	//
	// #1 Block IPv4 outbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Block IPv4 inbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Block IPv6 outbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Block IPv6 inbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	allowConditionsV4 := make([]wtFwpmFilterCondition0, 0, len(denyConditions)+len(except))
	allowConditionsV4 = append(allowConditionsV4, denyConditions...)
	for _, ip := range except {
		if !ip.Is4() {
			continue
		}
		allowConditionsV4 = append(allowConditionsV4, wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT32,
				value: uintptr(binary.BigEndian.Uint32(ip.AsSlice())),
			},
		})
	}

	storedPointers := make([]*wtFwpByteArray16, 0, len(except))
	allowConditionsV6 := make([]wtFwpmFilterCondition0, 0, len(denyConditions)+len(except))
	allowConditionsV6 = append(allowConditionsV6, denyConditions...)
	for _, ip := range except {
		if !ip.Is6() {
			continue
		}
		address := wtFwpByteArray16{byteArray16: ip.As16()}
		allowConditionsV6 = append(allowConditionsV6, wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_BYTE_ARRAY16_TYPE,
				value: uintptr(unsafe.Pointer(&address)),
			},
		})
		storedPointers = append(storedPointers, &address)
	}

	filter = wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weightAllow),
		numFilterConditions: uint32(len(allowConditionsV4)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&allowConditionsV4[0])),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID = uint64(0)

	//
	// #5 Allow IPv4 outbound DNS.
	//
	if len(allowConditionsV4) > len(denyConditions) {
		displayData, err := createWtFwpmDisplayData0("Allow DNS outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #6 Allow IPv4 inbound DNS.
	//
	if len(allowConditionsV4) > len(denyConditions) {
		displayData, err := createWtFwpmDisplayData0("Allow DNS inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	filter.filterCondition = (*wtFwpmFilterCondition0)(unsafe.Pointer(&allowConditionsV6[0]))
	filter.numFilterConditions = uint32(len(allowConditionsV6))

	//
	// #7 Allow IPv6 outbound DNS.
	//
	if len(allowConditionsV6) > len(denyConditions) {
		displayData, err := createWtFwpmDisplayData0("Allow DNS outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #8 Allow IPv6 inbound DNS.
	//
	if len(allowConditionsV6) > len(denyConditions) {
		displayData, err := createWtFwpmDisplayData0("Allow DNS inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	runtime.KeepAlive(storedPointers)

	return nil
}

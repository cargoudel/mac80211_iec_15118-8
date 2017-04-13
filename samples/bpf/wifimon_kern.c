/* Copyright (c) 2017 Intel Deutschland GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#define KBUILD_MODNAME "wifimon_test"
#include <uapi/linux/bpf.h>
#include <linux/ieee80211.h>
#include "bpf_helpers.h"

SEC("wifimon_no_data")
int wifimon_no_data(struct __sk_buff *skb)
{
	u8 fc1;
	int ret = bpf_skb_load_bytes(skb, 0, &fc1, sizeof(fc1));

	/* reject data frames */
	if ((fc1 & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA)
		return 0;

	/* reject beacon frames */
	if ((fc1 & (IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
			(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_BEACON))
		return 0;

	/* accept */
	return 1;
}

char _license[] SEC("license") = "GPL";

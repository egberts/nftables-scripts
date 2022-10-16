#!/bin/bash 

source nft-common.nft


# /etc/init.d/nftables save
$nft list ruleset > /etc/nftables.conf
